#ifndef __ROUTING_H__
#define __ROUTING_H__

#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <shared_mutex>
#include <unordered_map>
#include <vector>
#include <optional>
#include <list>

#include "io.h"
#include "udp_srv.h"

extern void print_hex(const uint8_t *buf, int sz);


struct ip_addr_t {
    uint8_t len{0};
    uint8_t buf[16]{};

    static ip_addr_t v4(uint32_t be)
    {
        ip_addr_t a;
        a.len = 4;
        std::memcpy(a.buf, &be, 4);
        return a;
    }

    static ip_addr_t v6(const uint8_t *be16)
    {
        ip_addr_t a;
        a.len = 16;
        std::memcpy(a.buf, be16, 16);
        return a;
    }

    bool operator==(const ip_addr_t &o) const noexcept
    {
        return len == o.len && std::memcmp(buf, o.buf, len) == 0;
    }

    static std::optional<ip_addr_t> parse(const std::string &txt);
};

struct ip_addr_hash {
    size_t operator()(const ip_addr_t &a) const noexcept
    {
        uint64_t h = 0;
        std::memcpy(&h, a.buf, 8);
        return std::hash<uint64_t>{}(h ^ a.len);
    }
};

struct routing_entry_t {
    io_t::endpoint_t ep;
    io_t *iface{nullptr};
    std::vector<ip_addr_t> addrs;
    std::chrono::steady_clock::time_point last_seen;
    bool local;
};

class routing_t : public std::unordered_map<ip_addr_t, routing_entry_t, ip_addr_hash>
{
   public:
    using clk = std::chrono::steady_clock;
    using seconds = std::chrono::seconds;

    explicit routing_t(seconds idle_timeout);

    void register_io(io_t *iface);
    void register_local_io(io_t *tun_iface, const ip_addr_t &my_ip);

   private:

    enum route_result_t {
        MALFORMED_PKT,
        DROP,
        BROADCAST,
        UNICAST
    };

    route_result_t route_frame(const uint8_t *pkt, size_t len, io_t &ingress);
    void purge_expired();

#pragma pack(push,1)
    struct ctl_hdr_t {
        uint8_t vers_pad;
        uint8_t type;
    };
    struct tlv_t {
        uint8_t len;
        uint8_t family;
        uint8_t addr[16];
    };
#pragma pack(pop)

    void handle_datagram(const io_t::endpoint_t &src_ep, const uint8_t *data, size_t len, io_t &ingres);
    io_t::receive_callback rx_cb = [this](const io_t::endpoint_t &from, const uint8_t *d, size_t n, io_t &iface) {
        spdlog::debug("routing: receive ");
        print_hex(d, n);

        this->handle_datagram(from, d, n, iface);
    };

    void announce_from(io_t *iface, bool bye = false);
    bool parse_control_frame(const uint8_t *, size_t, std::vector<ip_addr_t> &out_addrs, bool &is_bye) const;

    static constexpr uint8_t vers_nibble_ = 0xF;
    static constexpr uint8_t type_announce_ = 0x01;
    static constexpr uint8_t type_bye_ = 0x02;
    static constexpr uint8_t ipv4_broadcast[4] = {0xff,0xff,0xff,0xff};

    seconds idle_;
    ip_addr_t my_ip_{};
    std::list<io_t*> iface_list_;
    mutable std::shared_mutex mu_;
};

#endif
