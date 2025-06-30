#ifndef __TUN_H__
#define __TUN_H__

#include "io.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

class tun_if_t : public io_t
{
public:
    tun_if_t(std::string name,
             receive_callback rx_cb,
             std::uint16_t mtu = 1440, // 1536 - 14 - 20 - 8 - 13 - ... = ~1440
             std::string ip = "",
             uint8_t cidr = 24,
             unsigned queues = 1)
        : rx_cb_(std::move(rx_cb)),
          mtu_(mtu),
          running_(true)
    {
        if (queues == 0) {
            queues = 1;
        }

        fds_.reserve(queues);
        rx_thr_.reserve(queues);

        int flags = IFF_TUN | IFF_NO_PI | (queues > 1 ? IFF_MULTI_QUEUE : 0);

        for (unsigned q = 0; q < queues; ++q) {
            std::string tmp = name;
            int fd = tun_alloc(tmp, flags, mtu_);
            if (fd < 0) {
                throw std::runtime_error("tun_alloc() failed");
            }
            if_name_ = tmp;
            fds_.push_back(fd);
        }

        buf_len_ = mtu_ + 100;
        if (!ip.empty()) {
            configure_ipv4(if_name_, ip, cidr);
        } else {
            bring_up(if_name_);
        }

        for (int fd : fds_) {
            rx_thr_.emplace_back([this, fd] {
                char thread_name[15] = {};
                snprintf(thread_name, sizeof(thread_name), "tun-rx-%d", fd);
                set_thread_name(thread_name);
                rx_loop(fd);
            });
        }
    }

    ~tun_if_t() override { stop(); }

    void stop()
    {
        if (!running_.exchange(false)) {
            return;
        }

        for (int fd : fds_) {
            ::shutdown(fd, SHUT_RD);
        }
        for (auto &t : rx_thr_) {
            if (t.joinable()) {
                t.join();
            }
        }

        for (int fd : fds_) {
            ::close(fd);
        }
        fds_.clear();
    }

    void write(const endpoint_t &, const uint8_t *data, size_t len) override
    {
        int fd = fds_[tx_seq_.fetch_add(1) % fds_.size()]; // round-robin
        ssize_t n = ::write(fd, data, len);
        if (n < 0) {
            std::perror("tun_if_t: write");
        }
    }

    static void bring_up(const std::string &dev)
    {
        int s = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (s < 0) {
            throw std::runtime_error("socket()");
        }

        struct ifreq ifr{};
        std::strncpy(ifr.ifr_name, dev.c_str(), IFNAMSIZ);
        if (::ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
            ::close(s);
            throw std::runtime_error("SIOCGIFFLAGS");
        }
        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
        if (::ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
            ::close(s);
            throw std::runtime_error("SIOCSIFFLAGS");
        }
        ::close(s);
    }

    static void configure_ipv4(const std::string &dev, const std::string &ip, uint8_t cidr)
    {
        int s = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (s < 0) {
            throw std::runtime_error("socket()");
        }

        struct ifreq ifr{};
        std::strncpy(ifr.ifr_name, dev.c_str(), IFNAMSIZ);

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        if (::inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
            ::close(s);
            throw std::invalid_argument("bad IPv4 address");
        }
        std::memcpy(&ifr.ifr_addr, &addr, sizeof(addr));
        if (::ioctl(s, SIOCSIFADDR, &ifr) < 0) {
            ::close(s);
            throw std::runtime_error("SIOCSIFADDR");
        }

        uint32_t mask = (cidr == 32) ? 0xffffffffu : htonl(~((1u << (32 - cidr)) - 1));
        addr.sin_addr.s_addr = mask;
        std::memcpy(&ifr.ifr_netmask, &addr, sizeof(addr));
        if (::ioctl(s, SIOCSIFNETMASK, &ifr) < 0) {
            ::close(s);
            throw std::runtime_error("SIOCSIFNETMASK");
        }

        ::close(s);
        bring_up(dev);
    }

    const std::string &if_name() const { return if_name_; }
    std::uint16_t current_mtu() const { return mtu_; }

private:
    static int tun_alloc(std::string &dev, int flags, std::uint16_t mtu)
    {
        int fd = ::open("/dev/net/tun", O_RDWR | O_CLOEXEC);
        if (fd < 0)
            return -1;

        struct ifreq ifr{};
        if (!dev.empty()) {
            std::snprintf(ifr.ifr_name, IFNAMSIZ, "%s", dev.c_str());
        }
        ifr.ifr_flags = flags;

        if (::ioctl(fd, TUNSETIFF, &ifr) < 0) {
            ::close(fd);
            return -1;
        }
        int sndbuf = mtu + 100;
        ioctl(fd, TUNSETSNDBUF, &sndbuf);

        dev = ifr.ifr_name;
        int s = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (s < 0) {
            ::close(fd);
            return -1;
        }

        std::strncpy(ifr.ifr_name, dev.c_str(), IFNAMSIZ);
        ifr.ifr_mtu = mtu;

        int ok = ::ioctl(s, SIOCSIFMTU, &ifr);
        ::close(s);
        if (ok < 0) {
            ::close(fd);
            return -1;
        }

        return fd;
    }

    void rx_loop(int fd)
    {
        std::vector<uint8_t> buf(buf_len_);

        while (running_) {
            ssize_t n = ::read(fd, buf.data(), buf.size());
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                std::perror("tun_if_t: read");
                break;
            }

            if (n == 0) {
                continue;
            }

            static endpoint_t null_ep{};
            if (rx_cb_) {
                rx_cb_(null_ep, buf.data(), static_cast<size_t>(n), *this);
            }
        }
    }

    std::string if_name_;
    std::string ip_;
    std::vector<int> fds_;
    std::vector<std::thread> rx_thr_;
    receive_callback rx_cb_;

    std::uint16_t mtu_;
    size_t buf_len_;
    std::atomic_uint64_t tx_seq_{0};

    std::atomic<bool> running_;
};

#endif
