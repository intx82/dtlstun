#include "routing.h"

#include <spdlog/spdlog.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <spdlog/spdlog.h>

std::optional<ip_addr_t> ip_addr_t::parse(const std::string &txt)
{
    in6_addr v6;
    in_addr v4;
    if (inet_pton(AF_INET, txt.c_str(), &v4) == 1) {
        return ip_addr_t::v4(v4.s_addr);
    }

    if (inet_pton(AF_INET6, txt.c_str(), &v6) == 1) {
        return ip_addr_t::v6(reinterpret_cast<uint8_t*>(&v6));
    }

    return std::nullopt;
}


routing_t::routing_t(seconds idle)
    : idle_(idle) {}

void routing_t::register_io(io_t *iface)
{
    iface->set_rx_cb(rx_cb);
    iface->set_status_cb([this](io_t::state_t st, io_t &iface) {
        if (st == io_t::state_t::CONNECTED) {
            this->announce_from(&iface, false);
        } else if (st == io_t::state_t::NOT_CONNECTED) {
            this->announce_from(&iface, true);
        }
    });

    iface_list_.push_back (iface);
}

void routing_t::register_local_io(io_t* iface, const ip_addr_t &my_ip)
{
    std::unique_lock lk(mu_);
    my_ip_ = my_ip;
    iface->set_rx_cb(rx_cb);
    (*this)[my_ip] = routing_entry_t{{}, iface, {my_ip}, clk::now(), true};
    iface_list_.push_back(iface);
}

void routing_t::handle_datagram(const io_t::endpoint_t &from, const uint8_t *d, size_t n, io_t &ingress)
{
    uint8_t ver = reinterpret_cast<const iphdr *>(d)->version;
    purge_expired();

    if (n < 2 || ver != vers_nibble_) {
        return;
    }

    std::vector<ip_addr_t> addrs;
    bool is_bye = false;
    if (!parse_control_frame(d, n, addrs, is_bye)) {
        switch(route_frame(d, n, ingress))
        {
            case MALFORMED_PKT: spdlog::warn("Routing malformed packet"); return;
            case DROP:         spdlog::debug("Droping packet. Unknown recepient"); return;
            case BROADCAST: {
                for (std::pair<const ip_addr_t, routing_entry_t> &route : *this) {
                    const routing_entry_t& entry = std::get<1>(route);
                    entry.iface->write(entry.ep, d, n);
                }
            }; return;
            case UNICAST:
            default:
                return;
        }
    }

    std::unique_lock lk(mu_);
    if (is_bye) {
        for (auto &a : addrs) {
            this->erase(a);
        }
        return;
    }

    auto now = clk::now();
    for (auto &ip : addrs) {
        routing_entry_t &e = (*this)[ip];
        e.ep = from;
        e.iface = &ingress;
        e.last_seen = now;
        e.local = false;

        if (std::find(e.addrs.begin(), e.addrs.end(), ip) == e.addrs.end()) {
            e.addrs.push_back(ip);
        }
    }
}

routing_t::route_result_t routing_t::route_frame(const uint8_t *pkt, size_t len, io_t &ingress)
{
    if (len < sizeof(iphdr)) {
        return MALFORMED_PKT;
    }

    uint8_t ver = reinterpret_cast<const iphdr *>(pkt)->version;

    ip_addr_t dst{};
    if (ver == 4) {
        const iphdr *h = reinterpret_cast<const iphdr *>(pkt);
        if (h->ihl < 5) {
            return MALFORMED_PKT;
        }
        dst = ip_addr_t::v4(h->daddr);

        if (std::memcmp(dst.buf, ipv4_broadcast, 4) == 0) {
            return BROADCAST;
        }

        if ((dst.buf[0] >= 224) && (dst.buf[0] <= 239)) {
            return BROADCAST;
        }

    } else if (ver == 6) {
        if (len < sizeof(ip6_hdr)) {
            return MALFORMED_PKT;
        }
        const ip6_hdr *h = reinterpret_cast<const ip6_hdr *>(pkt);
        dst.len = 16;
        std::memcpy(dst.buf, &h->ip6_dst, 16);
    } else {
        return MALFORMED_PKT;
    }

    {
        if (this->size() <= 1) {
            return BROADCAST;
        }

        std::shared_lock lk(mu_);
        auto it = find(dst);
        if (it == end()) {
            return DROP;
        }

        const routing_entry_t &ent = it->second;
        if (ent.iface) {
            ent.iface->write(ent.ep, pkt, len);
            return UNICAST;
        }
    }
    return DROP;
}

void routing_t::purge_expired()
{
    auto now = clk::now();
    std::unique_lock lk(mu_);
    for (auto it = this->begin(); it != this->end();) {
        if (it->first == my_ip_) {
            ++it;
            continue;
        }
        if (now - it->second.last_seen > idle_) {
            it = this->erase(it);
        } else {
            ++it;
        }
    }
}

void routing_t::announce_from(io_t *iface, bool bye)
{
    uint8_t buf[2048] = {};
    if (my_ip_.len == 0) {
        return;
    }

    ctl_hdr_t hdr;
    hdr.vers_pad = (vers_nibble_ << 4);
    hdr.type = bye ? type_bye_ : type_announce_;

    int offset = sizeof(hdr);
    std::memcpy(buf, &hdr, sizeof(hdr));

    for (std::pair<const ip_addr_t, routing_entry_t> &route : *this) {
        tlv_t tlv{};
        const ip_addr_t& ip = std::get<0>(route);
        tlv.family = (ip.len == 4 ? 4 : 6);
        tlv.len = (ip.len == 4 ? 6 : 18);
        std::memcpy(tlv.addr, ip.buf, ip.len);
        std::memcpy(&buf[offset], &tlv, tlv.len);
        offset += tlv.len;
    }

    spdlog::debug("routing: Send announce: {}", offset);
    print_hex(buf, offset);

    iface->write({}, buf, offset);
}

bool routing_t::parse_control_frame(const uint8_t *d, size_t n, std::vector<ip_addr_t> &out, bool &is_bye) const
{
    if (n < sizeof(ctl_hdr_t)) {
        return false;
    }
    const ctl_hdr_t *hdr = reinterpret_cast<const ctl_hdr_t *>(d);

    is_bye = (hdr->type == type_bye_);
    if (hdr->type != type_announce_ && hdr->type != type_bye_) {
        return false;
    }

    size_t off = sizeof(ctl_hdr_t);
    while (off + sizeof(tlv_t) <= n) {
        const tlv_t *tlv = reinterpret_cast<const tlv_t *>(d + off);
        uint8_t len = tlv->len;

        if (len < 2 || off + len > n) {
            return false;
        }

        if (tlv->family == 4 && len == 6) {
            uint32_t be = 0;
            std::memcpy(&be, tlv->addr, 4);
            out.push_back(ip_addr_t::v4(be));
        } else if (tlv->family == 6 && len == 18) {
            ip_addr_t v6{};
            v6.len = 16;
            std::memcpy(v6.buf, tlv->addr, 16);
            out.push_back(v6);
        }

        off += len;
    }

    return !out.empty();
}
