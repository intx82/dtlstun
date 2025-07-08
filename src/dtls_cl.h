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

using namespace std::chrono_literals;

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
                  std::chrono::seconds idle_to = 2min)
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
        close_session();
        
        running_.exchange(false);
        usleep(250000);  // just to receive server-side encrypted alert

        itimerspec dis{};
        dis.it_value.tv_sec = 0;
        dis.it_value.tv_nsec = 100'000'000LL;
        timerfd_settime(timer_fd_, 0, &dis, nullptr);

        if (thr_.joinable()) {
            thr_.join();
        }

        close(timer_fd_);
        close(efd_);
    }

    void write(const endpoint_t &, const uint8_t *p, size_t n) override
    {
        spdlog::debug("dtls_client: Send DGRAM: {}:{} sz: {} State: {}", server_ep_.host, server_ep_.port, n, hs_names_[hs_state_]);

        if (hs_state_ != HANDSHAKE_DONE) {
            spdlog::debug("dtls_client: Timer: Re-arm handshake {}", hs_state_);
            hs_state_ = HANDSHAKE_IN_PROGRESS;
            rearm_timer(100ms);
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
        spdlog::debug("dtls_client: Timer Re-arm write");
        rearm_timer(idle_to_);
    }

    void handle_datagram(const endpoint_t &from, const uint8_t *d, size_t len)
    {
        if (from.host != server_ep_.host || from.port != server_ep_.port) {
            return;
        }

        spdlog::debug("dtls_client: Receive DGRAM: {}:{} sz: {} State: {}", from.host, from.port, len, hs_names_[hs_state_]);
        if ((ssl_ != nullptr ) && (hs_state_ != handshake_state_t::HANDSHAKE_NOT_STARTED)) {

            std::lock_guard<std::mutex> lock(io_mu_);
            if (BIO_write(in_bio_, d, (int)len) != (int)len) {
                print_ssl_err("BIO_write");
                return;
            }

            if (connected()) {
                pull_appdata();
            }

            last_io_ = now();
        }

        rearm_timer( hs_state_ != handshake_state_t::HANDSHAKE_DONE ? 100ms : idle_to_);
    }

    bool connected() const { return hs_state_ == handshake_state_t::HANDSHAKE_DONE; }

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
            spdlog::debug("dtls_client: Create_ssl: Free old ssl context");
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
        hs_state_ = handshake_state_t::HANDSHAKE_IN_PROGRESS;
    }

    void do_handshake()
    {
        if (ssl_ == nullptr) {
            create_ssl();
        }

        int ret = SSL_do_handshake(ssl_);
        if (ret == 1) {
            hs_state_ = handshake_state_t::HANDSHAKE_DONE;
            spdlog::info("dtls_client: Handshake done {}:{} ", server_ep_.host, server_ep_.port);
        } else {
            int err = SSL_get_error(ssl_, ret);
            if (err != SSL_ERROR_WANT_READ &&
                err != SSL_ERROR_WANT_WRITE) {
                print_ssl_err("SSL_do_handshake");
                close_session();
            }
        }
        pump_out();
    }

    void pull_appdata()
    {
        uint8_t buf[16384];
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
        while (BIO_ctrl_pending(out_bio_) > 0) {
            unsigned char hdr[13];
            {
                std::lock_guard<std::mutex> lg(io_mu_);
                int n = BIO_read(out_bio_, hdr, sizeof(hdr));
                if (n != 13) {
                    print_ssl_err("short hdr");
                    break;
                }
            }

            unsigned rec_len = (hdr[11] << 8) | hdr[12];
            std::vector<unsigned char> pkt(13 + rec_len);
            memcpy(pkt.data(), hdr, 13);
            {
                std::lock_guard<std::mutex> lg(io_mu_);
                int m = BIO_read(out_bio_, pkt.data() + 13, rec_len);
                if (m != (int)rec_len) {
                    print_ssl_err("short body");
                    break;
                }
            }

            send_(server_ep_, pkt.data(), pkt.size());
        }
    }

    using clk = std::chrono::steady_clock;
    static clk::time_point now() { return clk::now(); }

    std::chrono::microseconds update_ssl_deadline()
    {
        if (ssl_ == nullptr) {
            return 1s;
        }

        struct timeval tv;
        if (DTLSv1_get_timeout(ssl_, &tv) != 0) {
            return std::chrono::microseconds(tv.tv_sec * 1'000'000LL + tv.tv_usec);
        } else {
            return idle_to_;
        }
    }

    void rearm_timer(std::chrono::milliseconds fire_in)
    {
        clk::time_point next = clk::now() + fire_in;

        if (fire_in <= 0s) {
            spdlog::debug("dtls_client: Timer disable");
            itimerspec dis{};
            timerfd_settime(timer_fd_, 0, &dis, nullptr);
            return;
        }

        spdlog::debug("dtls_client: Timer fire in {} ms", fire_in.count());
        std::chrono::nanoseconds ns = std::chrono::time_point_cast<std::chrono::nanoseconds>(next).time_since_epoch();

        itimerspec its{};
        its.it_value.tv_sec = ns.count() / 1'000'000'000LL;
        its.it_value.tv_nsec = ns.count() % 1'000'000'000LL;

        if (its.it_value.tv_nsec >= 1'000'000'000) {
            its.it_value.tv_nsec -= 1'000'000'000;
            its.it_value.tv_sec++;
        }

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
        spdlog::debug("dtls_client: Timer fired. State: {}", hs_names_[hs_state_]);
        if (hs_state_ == handshake_state_t::HANDSHAKE_IN_PROGRESS) {
            do_handshake();
            rearm_timer(100ms);
        } else if (hs_state_ == handshake_state_t::SESSION_CLOSING) {

            if (ssl_) {
                if (!(SSL_get_shutdown(ssl_) & SSL_SENT_SHUTDOWN)) {
                    SSL_shutdown(ssl_);
                }
                pump_out();
                SSL_free(ssl_);
                ssl_ = nullptr;
            }

            hs_state_ = handshake_state_t::HANDSHAKE_NOT_STARTED;
            rearm_timer(idle_to_);
        } else if ((hs_state_ == handshake_state_t::HANDSHAKE_DONE) || (hs_state_ == HANDSHAKE_NOT_STARTED)) {
            rearm_timer(idle_to_);
        }
    }

    void close_session()
    {
        spdlog::warn("dtls_client: Session close {}:{}", server_ep_.host, server_ep_.port);
        hs_state_ = SESSION_CLOSING;
        rearm_timer(100ms);
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

    enum handshake_state_t {
        HANDSHAKE_NOT_STARTED = 0,
        HANDSHAKE_IN_PROGRESS,
        HANDSHAKE_DONE,
        SESSION_CLOSING,
        HANDSHAKE_MAX
    };

    const std::string hs_names_[handshake_state_t::HANDSHAKE_MAX] = {
        "Session closed",
        "Handshake in progress, Session closed",
        "Handshake done, Session established",
        "Session closing",
    };

    send_callback send_;
    endpoint_t server_ep_;
    receive_callback rx_cb_;

    SSL_CTX *ctx_{nullptr};
    SSL *ssl_{nullptr};
    BIO *in_bio_{nullptr};
    BIO *out_bio_{nullptr};

    handshake_state_t hs_state_{handshake_state_t::HANDSHAKE_NOT_STARTED};
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
        } else if (w & SSL_CB_ALERT) {
            str = "SSL_alert";
        } else {
            str = "undefined";
        }

        spdlog::debug("dtls_client: {}: {}", str, SSL_state_string_long(ssl));
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
        const char *dir = write_p ? ">" : "<";
        const char *ct = rt_name(content_type);

        spdlog::debug("dtls_client: {} {} - len: {} bytes", dir, ct, len);
    }
};

#endif
