#ifndef __DTLS_CLIENT_H__
#define __DTLS_CLIENT_H__

#include "io.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <unistd.h>

class dtls_client_t : public io_t
{
public:
    using send_callback =
        std::function<void(const io_t::endpoint_t &, const uint8_t *, size_t)>;

    dtls_client_t(send_callback send_cb,
                  endpoint_t server,
                  const std::string &ca_file,
                  const std::string &cert_file,
                  const std::string &key_file,
                  receive_callback rx_cb,
                  size_t mtu = 1440,
                  std::chrono::seconds idle_to = std::chrono::minutes(2))
        : send_(std::move(send_cb)),
          server_ep_(std::move(server)),
          rx_cb_(std::move(rx_cb)),
          idle_to_(idle_to),
          ca_file_(ca_file),
          cert_file_(cert_file),
          key_file_(key_file),
          mtu_(mtu),
          running_(true)
    {
        init_openssl();
        load_creds(ca_file_, cert_file_, key_file_);
        create_ssl();

        efd_ = epoll_create1(EPOLL_CLOEXEC);
        timer_fd_ = timerfd_create(CLOCK_MONOTONIC,
                                   TFD_NONBLOCK | TFD_CLOEXEC);

        epoll_event evt_ = {
            .events = EPOLLIN,
            .data = {
                .fd = timer_fd_,
            },
        };

        epoll_ctl(efd_, EPOLL_CTL_ADD, timer_fd_, &evt_);
        thr_ = std::thread([this] {
            set_thread_name("dtls-client-rx");
            timer_loop();
        });
        do_handshake();
    }

    ~dtls_client_t() override
    {
        running_ = false;
        uint64_t one = 1;
        ::write(timer_fd_, &one, sizeof(one));
        if (thr_.joinable()) {
            thr_.join();
        }

        if (ssl_) {
            SSL_free(ssl_);
        }

        if (ctx_) {
            SSL_CTX_free(ctx_);
        }

        close(timer_fd_);
        close(efd_);
    }

    void write(const endpoint_t &, const uint8_t *p, size_t n) override
    {
        if (!handshake_done_) {
            std::cerr << "dtls_client: Session closed. Reestablishing connection " << server_ep_.host << ":" << server_ep_.port << "\n";
            do_handshake();
            return;
        }

        size_t off = 0;
        while (off < n) {
            pump_out();
            int ret = SSL_write(ssl_, p + off, (int)(n - off));
            if (ret > 0) {
                off += ret;
                continue;
            }

            if (ret == 0) {
                continue;
            }

            int err = SSL_get_error(ssl_, ret);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                pump_out();
                continue;
            }

            print_ssl_err("SSL_write");
            close_session();
            return;
        }

        last_tx_ = now();
        pump_out();
        rearm_timer();
    }

    void handle_datagram(const endpoint_t &from, const uint8_t *d, size_t len)
    {
        if (from.host != server_ep_.host || from.port != server_ep_.port) {
            return;
        }

        last_rx_ = now();

        if (ssl_ == nullptr) {
            return;
        }

        {
            std::lock_guard<std::mutex> lock(io_mu_);
            if (BIO_write(in_bio_, d, (int)len) != (int)len) {
                print_ssl_err("BIO_write");
                return;
            }
        }

        if (!handshake_done_) {
            do_handshake();
        } else {
            pull_appdata();
        }

        pump_out();
        rearm_timer();
    }

    bool connected() const { return handshake_done_; }

private:
    void init_openssl()
    {
        SSL_library_init();
        SSL_load_error_strings();
        OPENSSL_init_ssl(0, nullptr);
        ctx_ = SSL_CTX_new(DTLS_client_method());

        if (!ctx_) {
            throw_ssl("SSL_CTX_new");
        }
    }

    void load_creds(const std::string &ca, const std::string &crt, const std::string &key)
    {
        if (!ca.empty() && SSL_CTX_load_verify_locations(ctx_, ca.c_str(), nullptr) != 1) {
            throw_ssl("load CA");
        }

        if (!crt.empty()) {
            if (SSL_CTX_use_certificate_file(ctx_, crt.c_str(),
                                             SSL_FILETYPE_PEM) != 1 ||
                SSL_CTX_use_PrivateKey_file(ctx_, key.c_str(),
                                            SSL_FILETYPE_PEM) != 1 ||
                SSL_CTX_check_private_key(ctx_) != 1) {
                throw_ssl("load cert/key");
            }
        }
    }

    void create_ssl()
    {
        if (ssl_) {
            SSL_free(ssl_);
            ssl_ = nullptr;
        }

        ssl_ = SSL_new(ctx_);
        if (!ssl_) {
            throw_ssl("SSL_new");
        }

        in_bio_ = BIO_new(BIO_s_mem());
        out_bio_ = BIO_new(BIO_s_mem());
        BIO_set_mem_eof_return(in_bio_, -1);
        BIO_set_mem_eof_return(out_bio_, -1);

        SSL_set_bio(ssl_, in_bio_, out_bio_);
        SSL_set_mtu(ssl_, mtu_);

        SSL_set_mode(ssl_, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE);
        SSL_set_connect_state(ssl_);
    }

    void do_handshake()
    {
        if (ssl_ == nullptr) {
            create_ssl();
        }

        int ret = SSL_do_handshake(ssl_);
        if (ret == 1) {
            handshake_done_ = true;
            std::cerr << "dtls_client: Handshake done  " << server_ep_.host << ":" << server_ep_.port << "\n";
        } else {
            int err = SSL_get_error(ssl_, ret);
            if (err != SSL_ERROR_WANT_READ &&
                err != SSL_ERROR_WANT_WRITE) {
                print_ssl_err("SSL_do_handshake");
                close_session();
            }
        }
        update_ssl_deadline();
        pump_out();
    }

    void pull_appdata()
    {
        uint8_t buf[2048];
        while (true) {
            int n = SSL_read(ssl_, buf, sizeof(buf));
            if (n <= 0) {
                int err = SSL_get_error(ssl_, n);
                if (err != SSL_ERROR_WANT_READ &&
                    err != SSL_ERROR_WANT_WRITE &&
                    err != SSL_ERROR_ZERO_RETURN) {
                    print_ssl_err("SSL_read");
                }

                if (SSL_get_shutdown(ssl_) & SSL_RECEIVED_SHUTDOWN) {
                    close_session();
                    return;
                }
                break;
            }

            if (rx_cb_) {
                rx_cb_(server_ep_, buf, (size_t)n, *this);
            }
        }
    }

    void pump_out()
    {
        uint8_t buf[2048];
        while (true) {
            std::lock_guard<std::mutex> lock(io_mu_);
            int n = BIO_read(out_bio_, buf, sizeof(buf));
            if (n <= 0) {
                break;
            }
            send_(server_ep_, buf, (size_t)n);
        }
    }

    using clk = std::chrono::steady_clock;
    static clk::time_point now() { return clk::now(); }

    void update_ssl_deadline()
    {
        struct timeval tv;
        if (DTLSv1_get_timeout(ssl_, &tv) != 0) {
            auto us = std::chrono::microseconds(tv.tv_sec * 1'000'000LL + tv.tv_usec);
            ssl_deadline_ = now() + us;
        } else {
            ssl_deadline_ = clk::time_point::max();
        }
    }

    void rearm_timer()
    {
        clk::time_point next = std::min(ssl_deadline_, last_rx_ + idle_to_);

        if (next == clk::time_point::max()) {
            itimerspec dis{};
            timerfd_settime(timer_fd_, 0, &dis, nullptr);
            return;
        }

        auto ns = std::chrono::time_point_cast<std::chrono::nanoseconds>(next).time_since_epoch();
        if (ns.count() < 0) {
            ns = std::chrono::nanoseconds(0);
        }

        itimerspec its{};
        its.it_value.tv_sec = ns.count() / 1'000'000'000LL;
        its.it_value.tv_nsec = ns.count() % 1'000'000'000LL;
        timerfd_settime(timer_fd_, TFD_TIMER_ABSTIME, &its, nullptr);
    }

    void timer_loop()
    {
        epoll_event ev;
        while (running_) {
            int n = epoll_wait(efd_, &ev, 1, -1);

            if (n < 0 && errno == EINTR) {
                continue;
            }

            if (ev.data.fd == timer_fd_) {
                uint64_t junk;
                ::read(timer_fd_, &junk, sizeof junk);
                on_tick();
            }
        }
    }

    void on_tick()
    {
        auto now_tp = now();

        if (now_tp >= ssl_deadline_) {

            if (DTLSv1_handle_timeout(ssl_) <= 0) {
                print_ssl_err("handle_timeout");
                close_session();
                return;
            }

            update_ssl_deadline();
            pump_out();
        }

        if (now_tp - last_rx_ > idle_to_) {
            close_session();
        }
        rearm_timer();
    }

    void close_session()
    {
        std::cerr << "dtls_client: Session close " << server_ep_.host << ":" << server_ep_.port << "\n";
        handshake_done_ = false;
        if (!ssl_) {
            return;
        }

        if (!(SSL_get_shutdown(ssl_) & SSL_SENT_SHUTDOWN)) {
            SSL_shutdown(ssl_);
        }

        pump_out();

        if (ssl_) {
            SSL_free(ssl_);
            ssl_ = nullptr;
        }
    }

    [[noreturn]] static void throw_ssl(const char *where)
    {
        char buf[256];
        ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
        throw std::runtime_error(std::string(where) + ": " + buf);
    }

    static void print_ssl_err(const char *where)
    {
        char buf[256];
        int err = ERR_get_error();
        if (err != 0) {
            ERR_error_string_n(err, buf, sizeof(buf));
            std::cerr << "dtls_client: " << where << ": " << buf << '\n';
        }
        ERR_clear_error();
    }

    send_callback send_;
    endpoint_t server_ep_;
    receive_callback rx_cb_;

    SSL_CTX *ctx_{nullptr};
    SSL *ssl_{nullptr};
    BIO *in_bio_{nullptr};
    BIO *out_bio_{nullptr};

    bool handshake_done_{false};
    clk::time_point ssl_deadline_{clk::time_point::max()};
    clk::time_point last_rx_{now()};
    clk::time_point last_tx_{now()};
    std::chrono::seconds idle_to_;
    std::mutex io_mu_;

    const std::string &ca_file_;
    const std::string &cert_file_;
    const std::string &key_file_;
    size_t mtu_;

    int efd_{-1};
    int timer_fd_{-1};
    std::thread thr_;
    std::atomic<bool> running_;
};

#endif
