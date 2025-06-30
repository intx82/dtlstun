#ifndef __UDP_H
#define __UDP_H

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "io.h"

class udp_server_t : public io_t
{
public:
    explicit udp_server_t(uint16_t listen_port,
                          receive_callback cb,
                          size_t buf_size = 2048)
        : cb_(std::move(cb)),
          buf_size_(buf_size),
          running_(true)
    {

        sock_ = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        if (sock_ < 0) {
            throw std::runtime_error("socket() failed");
        }

        struct sockaddr_in sa = {};
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
        sa.sin_port = htons(listen_port);

        if (bind(sock_, (sockaddr *)&sa, sizeof(sa)) < 0) {
            close(sock_);
            throw std::runtime_error("bind() failed");
        }

        efd_ = epoll_create1(EPOLL_CLOEXEC);
        if (efd_ < 0) {
            close(sock_);
            throw std::runtime_error("epoll_create1() failed");
        }

        struct epoll_event ev = {};
        ev.events = EPOLLIN | EPOLLET;
        ev.data.fd = sock_;
        if (epoll_ctl(efd_, EPOLL_CTL_ADD, sock_, &ev) < 0) {
            close(efd_);
            close(sock_);
            throw std::runtime_error("epoll_ctl(ADD) failed");
        }

        thr_ = std::thread([this] {
            set_thread_name("udp-rx");
            receive_loop();
        });
    }

    ~udp_server_t(void)
    {
        stop();
    }

    void stop(void)
    {
        if (!running_.exchange(false)) {
            return;
        }

        shutdown(sock_, SHUT_RDWR);
        close(sock_);
        close(efd_);
        if (thr_.joinable())
            thr_.join();
    }

    /* non-copyable, movable */
    udp_server_t(const udp_server_t &) = delete;
    udp_server_t &operator=(const udp_server_t &) = delete;

    udp_server_t(udp_server_t &&other) noexcept
        : sock_(other.sock_),
          efd_(other.efd_),
          cb_(std::move(other.cb_)),
          thr_(std::move(other.thr_)),
          buf_size_(other.buf_size_),
          running_(other.running_.load())
    {
        other.sock_ = -1;
        other.efd_ = -1;
        other.running_ = false;
    }

    udp_server_t &operator=(udp_server_t &&) = delete;

    void write(const io_t::endpoint_t &to,
               const uint8_t *data,
               size_t len)
    {
        struct sockaddr_in sa = {};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(to.port);

        if (inet_pton(AF_INET, to.host.c_str(), &sa.sin_addr) != 1)
            throw std::invalid_argument("udp_server_t: bad address");

        int retries = 20;
        for (;;) {
            ssize_t n = ::sendto(sock_, data, len, MSG_DONTWAIT,
                                 (sockaddr *)&sa, sizeof sa);
            if (n == (ssize_t)len) {
                return;
            }
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                if (retries-- == 0) {
                    return;
                }
                ::usleep(1000);
                continue;
            }

            std::perror("udp_server_t: sendto");
            return;
        }
    }

private:
    void receive_loop(void)
    {
        std::vector<uint8_t> buf(buf_size_);

        constexpr int MAXEV = 16;
        struct epoll_event events[MAXEV];

        while (running_) {
            int nready = epoll_wait(efd_, events, MAXEV, 1000);
            if (nready < 0) {
                if (errno == EINTR)
                    continue;
                std::perror("udp_server_t: epoll_wait");
                break;
            }
            if (nready == 0) {
                continue;
            }

            for (int i = 0; i < nready; ++i) {
                if (!(events[i].events & EPOLLIN)) {
                    continue;
                }

                for (;;) {
                    struct sockaddr_in peer = {};
                    socklen_t plen = sizeof(peer);

                    ssize_t n = recvfrom(sock_, buf.data(),
                                         buf.size(), 0,
                                         (sockaddr *)&peer,
                                         &plen);
                    if (n < 0) {
                        if (errno == EAGAIN ||
                            errno == EWOULDBLOCK)
                            break;
                        std::perror("udp_server_t: recvfrom");
                        break;
                    }

                    io_t::endpoint_t from;
                    char ip[INET_ADDRSTRLEN] = {};
                    inet_ntop(AF_INET, &peer.sin_addr,
                              ip, sizeof(ip));
                    from.host = ip;
                    from.port = ntohs(peer.sin_port);

                    if (cb_)
                        cb_(from, buf.data(),
                            (size_t)n, *this);
                }
            }
        }
    }

    int sock_{-1};
    int efd_{-1};
    receive_callback cb_;
    std::thread thr_;
    size_t buf_size_;
    std::atomic<bool> running_;
};

#endif
