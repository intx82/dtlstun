#ifndef __DTLS_H__
#define __DTLS_H__

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <spdlog/spdlog.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
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
#include <unordered_map>
#include <vector>

#include "io.h"

class dtls_server_t : public io_t
{
   public:
    using send_callback =
        std::function<void(const io_t::endpoint_t &, const uint8_t *, size_t)>;

    dtls_server_t(send_callback transport_send,
                  const std::string &ca_file,
                  const std::string &cert_file,
                  const std::string &key_file,
                  receive_callback app_cb,
                  size_t mtu = 1440,
                  std::chrono::steady_clock::duration idle_limit =
                      std::chrono::minutes(2))
        : send_(std::move(transport_send)),
          app_cb_(std::move(app_cb)),
          mtu_(mtu),
          idle_limit_(idle_limit)
    {
        init_openssl();
        load_credentials(ca_file, cert_file, key_file);
        setup_timer_thread();
    }

    void set_verify_peer(bool state)
    {
        if (state) {
            SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb);
            SSL_CTX_set_verify_depth(ctx_, 4);
        } else {
            SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, NULL);
        }
    }


    static int verify_cb(int ok, X509_STORE_CTX *ctx)
    {
        if (!ok) {
            spdlog::warn("dtls_server: client cert verify failed: {}", X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
        } else {
            spdlog::info("dtls_server: Certificate verify OK");
        }
        return ok;
    }


    ~dtls_server_t() override
    {
        spdlog::warn("dtls_server: exiting..\n");

        for (auto &kv : sessions_) {
            endpoint_t ep = parse_key(kv.first);

            session &s = *kv.second;
            if (!s.hs_done) {
                continue;
            }

            if (s.hs_done) {
                SSL_shutdown(s.ssl);
                pump_out_bio(s, ep);
            }
        }

        usleep(250000);  // to receive encrypted alert from clients

        running_ = false;
        uint64_t one = 1;
        ::write(exit_fd_, &one, sizeof(one));

        if (thr_.joinable()) {
            thr_.join();
        }

        for (auto &kv : sessions_) {
            free_session(kv.second);
        }

        SSL_CTX_free(ctx_);
        close(timer_fd_);
        close(efd_);
        close(exit_fd_);
    }

    void handle_datagram(const io_t::endpoint_t &from,
                         const uint8_t *pkt,
                         size_t len)
    {
        session *s = nullptr;
        {
            std::lock_guard<std::mutex> lg(mu_);
            s = get_or_create_session(from);
        }
        if (!s)
            return;
        {
            std::lock_guard<std::mutex> lg(io_mu_);
            if (BIO_write(s->in, pkt, (int)len) != (int)len) {
                print_ssl_error("BIO_write");
                return;
            }
        }
        s->last_rx = now();

        if (!s->hs_done) {
            int ret = SSL_do_handshake(s->ssl);
            if (ret == 1) {
                s->hs_done = true;
            } else if (ret == 0) {
                update_ssl_timer(*s);
                pump_out_bio(*s, from);
                arm_timerfd();
                return;
            } else {
                int err = SSL_get_error(s->ssl, ret);
                if ((err == SSL_ERROR_WANT_READ) || (err == SSL_ERROR_WANT_WRITE)) {
                    update_ssl_timer(*s);
                    pump_out_bio(*s, from);
                    arm_timerfd();
                    return;
                }
                print_ssl_error("SSL_do_handshake");
                return;
            }
        }

        while (true) { /* decrypt app data */
            uint8_t buf[16384];
            int n = SSL_read(s->ssl, buf, sizeof(buf));
            if (n <= 0) {
                int err = SSL_get_error(s->ssl, n);
                if (err != SSL_ERROR_WANT_READ &&
                    err != SSL_ERROR_WANT_WRITE &&
                    err != SSL_ERROR_ZERO_RETURN) {
                    print_ssl_error("SSL_read");
                }

                if (SSL_get_shutdown(s->ssl) & SSL_RECEIVED_SHUTDOWN) {
                    std::lock_guard<std::mutex> lg(mu_);
                    close_and_erase(from, sessions_.find(key(from))->second);
                    arm_timerfd();
                    return;
                }
                break;
            }
            app_cb_(from, buf, (size_t)n, *this);
        }
        update_ssl_timer(*s);
        pump_out_bio(*s, from);
        arm_timerfd();
    }

    void write(const io_t::endpoint_t &to, const uint8_t *data, size_t len) override
    {
        std::lock_guard<std::mutex> lg(mu_);
        auto it = sessions_.find(key(to));
        if (it == sessions_.end()) {
            spdlog::warn("dtls_server: no session for {}:{}", to.host, to.port);
            return;
        }
        session &s = *it->second;
        int ret = SSL_write(s.ssl, data, (int)len);
        if (ret <= 0) {
            int err = SSL_get_error(s.ssl, ret);
            if (err == SSL_ERROR_ZERO_RETURN) {
                close_and_erase(to, it->second);
            } else if (err != SSL_ERROR_WANT_WRITE &&
                       err != SSL_ERROR_WANT_READ) {
                print_ssl_error("SSL_write");
            }
            return;
        }
        update_ssl_timer(s);
        pump_out_bio(s, to);
        arm_timerfd();
    }

    void broadcast(const uint8_t *data,
                   size_t len,
                   const endpoint_t *except = nullptr)
    {
        std::lock_guard<std::mutex> lg(mu_);

        for (auto &kv : sessions_) {
            endpoint_t ep = parse_key(kv.first);

            if (except &&
                ep.host == except->host &&
                ep.port == except->port) {
                continue;
            }

            session &s = *kv.second;
            if (!s.hs_done) {
                continue;
            }

            int ret = SSL_write(s.ssl, data, (int)len);
            if (ret <= 0) {
                int err = SSL_get_error(s.ssl, ret);
                if (err == SSL_ERROR_ZERO_RETURN) {
                    close_and_erase(ep, kv.second);
                } else if (err != SSL_ERROR_WANT_READ &&
                           err != SSL_ERROR_WANT_WRITE) {
                    print_ssl_error("SSL_write");
                }
                continue;
            }
            update_ssl_timer(s);
            pump_out_bio(s, ep);
        }
        arm_timerfd();
    }

   private:
    using clk = std::chrono::steady_clock;
    static clk::time_point now() { return clk::now(); }

    struct session {
        SSL *ssl = nullptr;
        BIO *in = nullptr;
        BIO *out = nullptr;
        bool hs_done = false;
        clk::time_point last_rx;
        clk::time_point ssl_deadline{clk::time_point::max()};
    };

    static std::string key(const io_t::endpoint_t &e)
    {
        return e.host + ':' + std::to_string(e.port);
    }

    void init_openssl()
    {
        SSL_library_init();
        SSL_load_error_strings();
        OPENSSL_init_ssl(0, nullptr);
        ctx_ = SSL_CTX_new(DTLS_server_method());
        if (!ctx_) {
            throw_ssl("SSL_CTX_new");
        }
    }
    void load_credentials(const std::string &ca,
                          const std::string &crt,
                          const std::string &keyf)
    {
        if (SSL_CTX_use_certificate_file(ctx_, crt.c_str(), SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_use_PrivateKey_file(ctx_, keyf.c_str(), SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_check_private_key(ctx_) != 1) {
            throw_ssl("loading cert/key");
        }

        if (!ca.empty() &&
            SSL_CTX_load_verify_locations(ctx_, ca.c_str(), nullptr) != 1) {
            throw_ssl("load_verify_locations");
        }
    }

    session *get_or_create_session(const io_t::endpoint_t &peer)
    {
        auto k = key(peer);
        auto it = sessions_.find(k);
        if (it != sessions_.end()) {
            return it->second.get();
        }

        spdlog::info("dtls_server: Create new session for: {}:{}", peer.host, peer.port);
        auto up = std::make_unique<session>();
        session &s = *up;

        s.ssl = SSL_new(ctx_);
        if (!s.ssl) {
            print_ssl_error("SSL_new");
            return nullptr;
        }
        s.in = BIO_new(BIO_s_mem());
        s.out = BIO_new(BIO_s_mem());
        BIO_set_mem_eof_return(s.in, -1);
        BIO_set_mem_eof_return(s.out, -1);
        SSL_set_bio(s.ssl, s.in, s.out);
        SSL_set_mtu(s.ssl, mtu_);
        SSL_set_accept_state(s.ssl);

        s.last_rx = now();
        update_ssl_timer(s);

        auto p = sessions_.emplace(std::move(k), std::move(up));
        return p.first->second.get();
    }

    void pump_out_bio(session &s, const io_t::endpoint_t &to)
    {
        while (BIO_ctrl_pending(s.out) > 0) {
            unsigned char hdr[13];
            {
                std::lock_guard<std::mutex> lg(io_mu_);
                int n = BIO_read(s.out, hdr, sizeof(hdr));
                if (n != 13) {
                    print_ssl_error("short hdr");
                    break;
                }
            }

            unsigned rec_len = (hdr[11] << 8) | hdr[12];
            std::vector<unsigned char> pkt(13 + rec_len);
            memcpy(pkt.data(), hdr, 13);
            {
                std::lock_guard<std::mutex> lg(io_mu_);
                int m = BIO_read(s.out, pkt.data() + 13, rec_len);
                if (m != (int)rec_len) {
                    print_ssl_error("short body");
                    break;
                }
            }

            send_(to, pkt.data(), pkt.size());
        }
    }

    void update_ssl_timer(session &s)
    {
        timeval tv;
        if (DTLSv1_get_timeout(s.ssl, &tv) != 0) {
            auto us = std::chrono::microseconds(tv.tv_sec * 1'000'000LL + tv.tv_usec);
            s.ssl_deadline = now() + us;
        } else {
            s.ssl_deadline = clk::time_point::max();
        }
    }

    clk::time_point session_idle_deadline(const session &s) const
    {
        return s.last_rx + idle_limit_;
    }

    void setup_timer_thread()
    {
        efd_ = epoll_create1(EPOLL_CLOEXEC);
        timer_fd_ = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);

        exit_fd_ = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        epoll_event _evt = {
            .events = EPOLLIN,
            .data = {.fd = timer_fd_},
        };

        epoll_ctl(efd_, EPOLL_CTL_ADD, timer_fd_, &_evt);
        _evt.data.fd = exit_fd_;
        epoll_ctl(efd_, EPOLL_CTL_ADD, exit_fd_, &_evt);

        thr_ = std::thread([this] {
            set_thread_name("dtls-srv-rx");
            timer_loop();
        });
    }

    void arm_timerfd()
    {
        clk::time_point earliest = clk::time_point::max();

        for (auto &kv : sessions_) {
            const session &s = *kv.second;
            earliest = std::min(earliest, s.ssl_deadline);
            earliest = std::min(earliest, session_idle_deadline(s));
        }
        if (earliest == clk::time_point::max()) {
            itimerspec dis{};
            timerfd_settime(timer_fd_, 0, &dis, nullptr);
            return;
        }

        auto ns = std::chrono::time_point_cast<std::chrono::nanoseconds>(earliest).time_since_epoch();
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
        constexpr int MAXEV = 4;
        epoll_event evs[MAXEV];

        while (running_) {
            int n = epoll_wait(efd_, evs, MAXEV, -1);
            if (n < 0 && errno == EINTR)
                continue;

            for (int i = 0; i < n; ++i) {
                int fd = evs[i].data.fd;
                if (fd == timer_fd_) {
                    uint64_t junk;
                    ::read(timer_fd_, &junk, sizeof(junk));
                    on_tick();
                } else if (fd == exit_fd_) {
                    uint64_t junk;
                    ::read(exit_fd_, &junk, sizeof(junk));
                    running_ = false;
                    break;
                }
            }
        }
    }

    void on_tick()
    {
        auto now_tp = now();
        std::lock_guard<std::mutex> lg(mu_);

        for (auto it = sessions_.begin(); it != sessions_.end();) {
            session &s = *it->second;
            bool erase = false;

            if (now_tp >= s.ssl_deadline) {
                if (DTLSv1_handle_timeout(s.ssl) <= 0) {
                    print_ssl_error("handle_timeout");
                    erase = true;
                } else {
                    update_ssl_timer(s);
                    io_t::endpoint_t ep = parse_key(it->first);
                    pump_out_bio(s, ep);
                }
            }

            if (now_tp - s.last_rx > idle_limit_) {
                close_and_erase(parse_key(it->first), it->second);
                arm_timerfd();
                return;
            }

            if (erase) {
                it = sessions_.erase(it);
            } else {
                ++it;
            }
        }
        arm_timerfd();
    }

    static io_t::endpoint_t parse_key(const std::string &k)
    {
        auto pos = k.find(':');
        return {k.substr(0, pos), static_cast<uint16_t>(std::stoi(k.substr(pos + 1)))};
    }

    void free_session(std::unique_ptr<session> &up)
    {
        if (up) {
            SSL_free(up->ssl), up.reset();
        }
    }

    [[noreturn]] static void throw_ssl(const char *where)
    {
        char buf[256];
        ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
        throw std::runtime_error(std::string(where) + ": " + buf);
    }

    static void print_ssl_error(const char *where)
    {
        char buf[256];
        int err = ERR_get_error();
        if (err != 0) {
            ERR_error_string_n(err, buf, sizeof(buf));
            spdlog::error("dtls_server: {}: {}", where, buf);
        }
        ERR_clear_error();
    }

    void close_and_erase(const io_t::endpoint_t &ep,
                         std::unique_ptr<session> &up)
    {
        spdlog::warn("dtls_server: Closing session for: {}:{}", ep.host, ep.port);
        session &s = *up;
        if (s.hs_done) {
            if (!(SSL_get_shutdown(s.ssl) & SSL_SENT_SHUTDOWN)) {
                SSL_shutdown(s.ssl);
                pump_out_bio(s, ep);
            }
        }
        free_session(up);
        sessions_.erase(key(ep));
    }

    SSL_CTX *ctx_{nullptr};
    send_callback send_;
    receive_callback app_cb_;
    size_t mtu_;
    std::chrono::steady_clock::duration idle_limit_;

    std::unordered_map<std::string, std::unique_ptr<session>> sessions_;
    std::mutex mu_;
    std::mutex io_mu_;

    int efd_{-1}, timer_fd_{-1}, exit_fd_{-1};
    std::thread thr_;
    std::atomic<bool> running_{true};

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

        spdlog::debug("dtls_server: {} {} - len: {} bytes", dir, ct, len);
    }
};

#endif
