#ifndef __DTLS_CLIENT_H__
#define __DTLS_CLIENT_H__

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <spdlog/spdlog.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <unistd.h>

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

#include "io.h"

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

    void set_verify_peer(bool state)
    {
        if (state) {
            SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
            SSL_CTX_set_verify_depth(ctx_, 4);
        } else {
            SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, NULL);
        }
    }



    static int verify_cb(int ok, X509_STORE_CTX *ctx)
    {
        if (!ok) {
            spdlog::warn("dtls_client: client cert verify failed: {}", X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
        } else {
            spdlog::info("dtls_client: Certificate verify OK");
        }
        return ok;
    }

    ~dtls_client_t() override
    {
        stop();
    }

    void stop()
    {
        spdlog::info("DTLS-Client exiting.. Sending Encrypted-Alert to the server");
        SSL_shutdown(ssl_);
        pump_out();

        running_.exchange(false);
        usleep(250000);  // just to receive server-side encrypted alert

        itimerspec dis{};
        dis.it_value.tv_sec = 0;
        dis.it_value.tv_nsec = 250'000'000LL;
        timerfd_settime(timer_fd_, 0, &dis, nullptr);

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
        spdlog::debug("dtls_client: Send DGRAM: {}:{} sz: {}", server_ep_.host, server_ep_.port, n);

        if (!handshake_done_) {
            ssl_deadline_ = now() + std::chrono::seconds(1);
            rearm_timer();
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

        last_io_ = now();
        pump_out();
        rearm_timer();
    }

    void handle_datagram(const endpoint_t &from, const uint8_t *d, size_t len)
    {
        if (from.host != server_ep_.host || from.port != server_ep_.port) {
            return;
        }

        spdlog::debug("dtls_client: Receive DGRAM: {}:{} sz: {}", from.host, from.port, len);
        if (ssl_ == nullptr) {
            rearm_timer();
            return;
        }

        last_io_ = now();
        {
            std::lock_guard<std::mutex> lock(io_mu_);
            if (BIO_write(in_bio_, d, (int)len) != (int)len) {
                print_ssl_err("BIO_write");
                return;
            }
        }

        if (handshake_done_) {
            pull_appdata();
        }

        if (ssl_ != nullptr) {
            pump_out();
        }
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
            spdlog::info("dtls_client: Handshake done {}:{} ", server_ep_.host, server_ep_.port);
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
        while (running_) {
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
        while (running_) {
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
            ssl_deadline_ = now() + std::chrono::microseconds(tv.tv_sec * 1'000'000LL + tv.tv_usec);
        } else {
            ssl_deadline_ = clk::time_point::max();
        }
    }

    void rearm_timer()
    {
        clk::time_point next = std::min(ssl_deadline_, last_io_ + idle_to_);

        if (next == clk::time_point::max()) {
            itimerspec dis{};
            timerfd_settime(timer_fd_, 0, &dis, nullptr);
            return;
        }

        if (next < clk::now()) {
            next = clk::now() + idle_to_;
        }

        std::chrono::nanoseconds ns = std::chrono::time_point_cast<std::chrono::nanoseconds>(next).time_since_epoch();
        if (!running_) {
            ns = clk::now().time_since_epoch();
        }

        itimerspec its{};
        its.it_value.tv_sec = ns.count() / 1'000'000'000LL;
        its.it_value.tv_nsec = ns.count() % 1'000'000'000LL;

        if (its.it_value.tv_nsec >= 1'000'000'000) {
            its.it_value.tv_nsec -= 1'000'000'000;
            its.it_value.tv_sec++;
        }

        spdlog::debug("dtls_client: Timer fire in {} ms; Now {} ms",
                      std::chrono::duration_cast<std::chrono::milliseconds>(next - clk::now()).count(),
                      std::chrono::duration_cast<std::chrono::milliseconds>(clk::now().time_since_epoch()).count());

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

        if (!handshake_done_ || ssl_ == nullptr) {
            spdlog::info("dtls_client: Session closed. Reestablishing connection {}:{}", server_ep_.host, server_ep_.port);
            do_handshake();
            rearm_timer();
            return;
        }

        if (now_tp >= ssl_deadline_) {
            if (ssl_ != nullptr) {
                if (DTLSv1_handle_timeout(ssl_) <= 0) {
                    print_ssl_err("handle_timeout");
                    close_session();
                    return;
                }

                update_ssl_deadline();
                pump_out();
            }
        }

        if (now_tp - last_io_ > idle_to_) {
            close_session();
        }

        rearm_timer();
    }

    void close_session()
    {
        spdlog::warn("dtls_client: Session close {}:{}", server_ep_.host, server_ep_.port);
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
            spdlog::error("dtls_client: {}: {}", where, buf);
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
    clk::time_point last_io_{now()};
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

   public:

    void enable_debug()
    {
        SSL_CTX_set_info_callback(ctx_, info_cb);
        SSL_CTX_set_msg_callback(ctx_, msg_cb);
        SSL_CTX_set_msg_callback_arg(ctx_, this);
    }

   private:
    static void info_cb(const SSL *ssl, int where, int ret)
    {
        const char *str;
        int w = where & ~SSL_ST_MASK;

        if (w & SSL_ST_CONNECT) {
            str = "SSL_connect";
        } else if (w & SSL_ST_ACCEPT) {
            str = "SSL_accept";
        } else {
            str = "undefined";
        }

        if (where & SSL_CB_LOOP) {
            spdlog::debug("dtls_client: {}: {}", str, SSL_state_string_long(ssl));
        } else if (where & SSL_CB_EXIT) {
            if (ret == 0) {
                spdlog::debug("dtls_client: {}: failed in {}", str, SSL_state_string_long(ssl));
            }
        }
    }

    static const char *rt_name(int ct)
    {
        switch ((uint8_t)ct) {
            case SSL3_RT_HANDSHAKE:
                return "HS";
            case SSL3_RT_ALERT:
                return "AL";
            case SSL3_RT_CHANGE_CIPHER_SPEC:
                return "CC";
            case SSL3_RT_APPLICATION_DATA:
                return "AP";
#ifdef DTLS1_RT_HEARTBEAT
            case DTLS1_RT_HEARTBEAT:
                return "HB";
#endif
            default:
                return "??";
        }
    }

    static void msg_cb(int write_p, int ver, int content_type,
                       const void *buf, size_t len, SSL *ssl, void *arg)
    {
        const char *dir = write_p ? "→" : "←";
        const char *ct = rt_name(content_type);

        spdlog::debug("dtls_server: {} {} - len: {} bytes", dir, ct, len);
    }
};

#endif
