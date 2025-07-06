#include "arg_parse.h"
#include <cstdint>
#include <cstdlib>
#include <getopt.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

static void arg_usage(const char *prog)
{
    std::cerr <<
        R"(Usage:
  # server on 4444
  )" << prog << R"( --mode server --cert server.pem --key server.key --tun-ip 10.0.0.1/24

  # client to 1.2.3.4:4444
  )" << prog << R"( --mode client --remote 1.2.3.4:4444 --ca ca.pem --tun-ip 10.0.0.2/24

Options:
  -m,--mode {server|client|bridge}   Working mode (default server)
  -p,--port PORT                     Listen port (server/bridge)
  -r,--remote IP:PORT                Remote DTLS server (client/bridge)
  --ca FILE                          CA PEM (default ca.pem)
  --cert FILE                        Certificate PEM
  --key FILE                         Private key PEM
  --tun  NAME                        TUN interface name (bridge)
  --mtu BYTES                        MTU for TUN (default 1420)
  -t,--idle SECS                     Idle timeout (default 120)
  -v,--verbose                       Verbose log
  -i,--tun-ip                        TUN Interface IP address with netmask (example: 10.0.0.1/24)
  -d,--daemon                        Run as daemon
  -h,--help                          Show this help
)";
}

/*---------------------------------------------------------------*/
arg_opts_t parse_args(int argc, char **argv)
{
    arg_opts_t opt;
    static const option long_opts[] = {
        {"mode", required_argument, 0, 'm'},
        {"port", required_argument, 0, 'p'},
        {"remote", required_argument, 0, 'r'},
        {"ca", required_argument, 0, 0},
        {"cert", required_argument, 0, 0},
        {"key", required_argument, 0, 0},
        {"tun", required_argument, 0, 0},
        {"mtu", required_argument, 0, 0},
        {"idle", required_argument, 0, 't'},
        {"tun-ip", required_argument, 0, 'i'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {"daemon", no_argument, 0, 'd'},
        {0, 0, 0, 0}};
    int c, idx;
    while ((c = getopt_long(argc, argv, "m:p:r:t:i:vhd", long_opts, &idx)) != -1) {
        switch (c) {
        case 'm':
            if (std::string{optarg} == "server") {
                opt.mode = arg_opts_t::mode_t::SERVER;
            } else if (std::string{optarg} == "client") {
                opt.mode = arg_opts_t::mode_t::CLIENT;
            } else if (std::string{optarg} == "bridge") {
                opt.mode = arg_opts_t::mode_t::BRIDGE;
            } else {
                arg_usage(argv[0]);
                std::exit(1);
            }
            break;
        case 'p':
            opt.listen_port = std::stoi(optarg);
            break;
        case 'r': {
            std::string s{optarg};
            auto pos = s.find(':');
            if (pos == std::string::npos) {
                arg_usage(argv[0]);
                std::exit(1);
            }
            opt.remote_ip = s.substr(0, pos);
            opt.remote_port = static_cast<uint16_t>(std::stoi(s.substr(pos + 1)));
        } break;
        case 'i': {
            std::string s{optarg};
            auto pos = s.find('/');
            if (pos != std::string::npos) {
                opt.tun_cidr = static_cast<uint16_t>(std::stoi(s.substr(pos + 1)));
            }
            opt.tun_ip = s.substr(0, pos);
        } break;
        case 't':
            opt.idle_sec = std::stoi(optarg);
            break;
        case 'v':
            opt.verbose = true;
            break;
        case 'd':
            opt.daemon = true;
            break;
        case 0: /* long only */
            if (std::string{long_opts[idx].name} == "ca") {
                opt.ca_file = optarg;
            } else if (std::string{long_opts[idx].name} == "cert") {
                opt.cert_file = optarg;
            } else if (std::string{long_opts[idx].name} == "key") {
                opt.key_file = optarg;
            } else if (std::string{long_opts[idx].name} == "tun") {
                opt.tun_name = optarg;
            } else if (std::string{long_opts[idx].name} == "mtu") {
                opt.mtu = std::stoi(optarg);
            }
            break;
        case 'h':
            arg_usage(argv[0]);
            std::exit(0);
        default:
            arg_usage(argv[0]);
            std::exit(1);
        }
    }

    if (opt.tun_ip.empty()) {
        std::cerr << "TUN IP address required\n";
        arg_usage(argv[0]);
        std::exit(1);
    }

    if (opt.mode != arg_opts_t::mode_t::SERVER) {
        if (opt.remote_ip.empty() || opt.remote_port == 0) {
            std::cerr << "remote address required in client/bridge mode\n";
            std::exit(1);
        }

        if (opt.ca_file.empty()) {
            std::cerr << "CA required\n";
            arg_usage(argv[0]);
            std::exit(1);
        }
    }

    if (opt.mode != arg_opts_t::mode_t::CLIENT) {
        if (opt.cert_file.empty()) {
            std::cerr << "Server side certificate required\n";
            arg_usage(argv[0]);
            std::exit(1);
        }
        
        if (opt.key_file.empty()) {
            std::cerr << "Server side key required\n";
            arg_usage(argv[0]);
            std::exit(1);
        }
    }

    return opt;
}
