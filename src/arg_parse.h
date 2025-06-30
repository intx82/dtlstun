#ifndef __ARG_PARSE_H__
#define __ARG_PARSE_H__

#include <stddef.h>
#include <stdint.h>
#include <string>

struct arg_opts_t
{
    enum class mode_t
    {
        SERVER,
        CLIENT,
        BRIDGE
    } mode = mode_t::SERVER;

    uint16_t listen_port = 4444;
    std::string remote_ip = "";
    uint16_t remote_port = 0;

    std::string ca_file = "";
    std::string cert_file = "";
    std::string key_file = "";

    std::string tun_name = "tun0";
    uint16_t mtu = 1420;
    std::string tun_ip = "";
    uint8_t tun_cidr = 24;

    uint32_t idle_sec = 120;
    bool verbose = false;
    bool daemon  = false;
};

arg_opts_t parse_args(int argc, char **argv);

#endif
