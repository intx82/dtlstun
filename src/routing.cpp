#include "routing.h"

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <spdlog/spdlog.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>

using namespace std::chrono_literals;

std::optional<ip_addr_t> ip_addr_t::parse(const std::string &txt)
{
    in6_addr v6;
    in_addr v4;
    if (inet_pton(AF_INET, txt.c_str(), &v4) == 1) {
        return ip_addr_t::v4(v4.s_addr);
    }

    if (inet_pton(AF_INET6, txt.c_str(), &v6) == 1) {
        return ip_addr_t::v6(reinterpret_cast<uint8_t *>(&v6));
    }

    return std::nullopt;
}

std::string ip_addr_t::to_string() const
{
    if (len == 4) {
        char ret[16] = {};
        snprintf(ret, sizeof(ret), "%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3]);
        return std::string(ret);
    } else if (len == 16) {
        char tmp[48] = {};
        inet_aton(tmp, (in_addr *)buf);
        return std::string(tmp);
    }

    return "Unknown IP";
}

routing_t::routing_t() : running_(true)
{
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
        io_t::set_thread_name("routing");
        timer_loop();
    });

    rearm_timer(60s);
}

void routing_t::stop()
{
    running_.exchange(false);
    rearm_timer(1ms);

    if (thr_.joinable()) {
        thr_.join();
    }

    close(timer_fd_);
    close(efd_);
}

routing_t::~routing_t()
{
    stop();
}

void routing_t::timer_loop()
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

    client_iface_ = nullptr;
    server_iface_ = nullptr;
    tun_iface_ = nullptr;
}

void routing_t::on_tick()
{
    spdlog::debug("routing: Timer fired");
    send_router_discovery();
    rearm_timer(60s);
}

void routing_t::rearm_timer(std::chrono::milliseconds fire_in)
{
    clk::time_point next = clk::now() + fire_in;

    if (fire_in <= 0s) {
        spdlog::debug("routing: Timer disable");
        itimerspec dis{};
        timerfd_settime(timer_fd_, 0, &dis, nullptr);
        return;
    }

    spdlog::debug("routing: Timer fire in {} ms", fire_in.count());
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

void routing_t::register_io(dtls_client_t *iface)
{
    spdlog::debug("router: Registering io");
    client_iface_ = iface;
    iface->set_rx_cb(rx_cb);
}

void routing_t::register_io(dtls_server_t *iface)
{
    spdlog::debug("router: Registering io");
    server_iface_ = iface;
    iface->set_rx_cb(rx_cb);
}

void routing_t::register_local_io(io_t *iface, const ip_addr_t &my_ip)
{
    spdlog::debug("router: Registering tun iface");
    std::unique_lock lk(mu_);
    my_ip_ = my_ip;
    tun_iface_ = iface;
    iface->set_rx_cb(rx_cb);
    (*this)[my_ip] = routing_entry_t{{}, iface, 1};
}

void routing_t::handle_datagram(const io_t::endpoint_t &from, const uint8_t *pkt, size_t len, io_t &ingress)
{
    uint8_t ver = reinterpret_cast<const iphdr *>(pkt)->version;

    if ((len < sizeof(iphdr)) || ((ver != 4) && (ver != 6))) {
        spdlog::warn("routing: Receive malformed packet");
        return;
    }

    ip_addr_t dst{};
    ip_addr_t src{};

    if (ver == 4) {
        const iphdr *h = reinterpret_cast<const iphdr *>(pkt);

        if (h->ihl < 5) {
            spdlog::warn("routing: Receive malformed packet");
            return;
        }

        dst = ip_addr_t::v4(h->daddr);
        src = ip_addr_t::v4(h->saddr);
        spdlog::debug("routing: Route IPv4 packet to: {} from: {} (via {}:{})", dst.to_string(), src.to_string(), from.host, from.port);

        if (src != my_ip_) {
            add_route(src, from, ingress, -1);
        } else if ((src == my_ip_) && (&ingress != tun_iface_)) {
            spdlog::debug("routing: Drop. Found own ip in source, and it came not from TUN");
            return;
        }

        if (h->ttl == 1) {
            icmp_advert_process(from, pkt, len, ingress);
            spdlog::debug("routing: Drop. TTL = 0");
            return;
        }

        if (std::memcmp(dst.buf, ipv4_broadcast, 4) == 0) {
            broadcast(pkt, len, &from);
            return;
        }

        if ((dst.buf[0] >= 224) && (dst.buf[0] <= 239)) {
            broadcast(pkt, len, &from);
            return;
        }

        {
            std::shared_lock lk(mu_);
            auto it = find(dst);
            if (it == end()) {
                send_router_discovery();
                broadcast(pkt, len, &from);
                return;
            }

            const routing_entry_t &ent = it->second;
            if (ent.iface) {
                unicast(*ent.iface, ent.ep, pkt, len);
            }
        }
    }
}

void routing_t::broadcast(const uint8_t *d, size_t n, const io_t::endpoint_t *except) const
{
    spdlog::debug("routing: Send broadcast packet sz: {} except: {}:{}", n,
                  except == nullptr ? "local" : except->host,
                  except == nullptr ? "-" : std::to_string(except->port));
    print_hex(d, n);

    if (client_iface_ && (except == nullptr || except->empty())) {
        client_iface_->write({}, d, n);
    }

    if (server_iface_) {
        server_iface_->broadcast(d, n, except);
    }

    if (tun_iface_) {
        tun_iface_->write({}, d, n);
    }
}

void routing_t::unicast(io_t &iface, const io_t::endpoint_t &ep, const uint8_t *d, size_t n) const
{
    spdlog::debug("routing: Send unicast packet to {}:{} sz: {}", ep.host, ep.port, n);
    print_hex(d, n);
    iface.write(ep, d, n);
}

uint16_t routing_t::icmp_checksum(const void *data, std::size_t len)
{
    const uint8_t *p = static_cast<const uint8_t *>(data);
    uint32_t sum = 0;

    while (len > 1) {
        sum += (p[0] << 8) | p[1];
        p += 2;
        len -= 2;
    }

    if (len) {
        sum += p[0] << 8;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return static_cast<uint16_t>(~sum);
}

void routing_t::add_route(ip_addr_t &src, const io_t::endpoint_t &from, io_t &ingress, int32_t prio)
{
    if (src != my_ip_) {
        std::unique_lock lk(mu_);
        auto it = find(src);
        if (it == end()) {
            spdlog::warn("routing: Add new route: {} via {}:{} prio: {}", src.to_string(), from.host, from.port, prio);
            (*this)[src] = routing_entry_t{from, &ingress, 0};
        } else if ((*this)[src].prio <= prio) {
            spdlog::warn("routing: Replace route: {} via {}:{} prio: {} old-prio: {}", src.to_string(), from.host, from.port, prio, (*this)[src].prio);
            (*this)[src] = routing_entry_t{from, &ingress, prio};
        }
    }
}

void routing_t::icmp_advert_process(const io_t::endpoint_t &from, const uint8_t *pkt, size_t len, io_t &ingress)
{
    auto ip = reinterpret_cast<const iphdr *>(pkt);
    if (ip->version == 4 && ip->protocol != IPPROTO_ICMP) {
        return;
    }

    if (len < (size_t)(ip->ihl << 2)) {
        return;
    }

    auto icmp = reinterpret_cast<const icmphdr *>(&pkt[ip->ihl << 2]);
    if (icmp->type != ICMP_ROUTERADVERT || icmp->code != 0) {
        return;
    }

    const uint8_t *ra = reinterpret_cast<const uint8_t *>(icmp) + offsetof(iphdr, id);
    uint8_t count = ra[0];

    if (ra[1] != 2) {
        return;
    }

    const uint32_t *entry = reinterpret_cast<const uint32_t *>(ra + 4);

    for (int idx = 0; idx < count; idx++) {
        auto src = ip_addr_t::v4(entry[idx << 1]);
        int32_t prio = entry[(idx << 1) + 1];

        add_route(src, from, ingress, prio);
    }
}

void routing_t::send_router_discovery()
{
    uint8_t pkt[sizeof(iphdr) + 4 + 4 + this->size() * 8]{};

    auto ip = reinterpret_cast<iphdr *>(pkt);

    ip->ihl = 5;
    ip->version = 4;
    ip->ttl = 1;
    ip->protocol = IPPROTO_ICMP;
    ip->tot_len = htons(sizeof(pkt));
    memcpy((uint8_t *)&ip->saddr, my_ip_.buf, 4);
    memcpy((uint8_t *)&ip->daddr, ipv4_broadcast, 4);

    auto icmp = reinterpret_cast<icmphdr *>(&pkt[sizeof(iphdr)]);
    icmp->type = 9;
    icmp->code = 0;

    uint8_t *ra = reinterpret_cast<uint8_t *>(icmp) + offsetof(iphdr, id);
    ra[0] = this->size();  //  Num Addrs
    ra[1] = 2;             // Addr Entry Size
    *reinterpret_cast<uint16_t *>(ra + 2) = htons(120);

    uint32_t *entry = reinterpret_cast<uint32_t *>(ra + 4);

    int idx = 0;
    for (auto &a : *this) {
        const ip_addr_t &addr = std::get<0>(a);
        auto &route = std::get<1>(a);
        if (addr.len == 4) {
            memcpy((uint8_t *)&entry[idx], addr.buf, 4);
            entry[idx + 1] = route.prio - 1;
            idx += 2;
        }
    }

    icmp->checksum = htons(icmp_checksum(icmp, sizeof(pkt) - sizeof(iphdr)));

    broadcast(pkt, sizeof(pkt), nullptr);
}
