#include "arg_parse.h"
#include <cstdint>
#include <cstdlib>
#include <getopt.h>
#include <iostream>
#include <sstream>
#include <cstring>
#include <string>
#include <vector>

static void arg_usage(const char *prog)
{
    std::cerr <<
        R"(Usage:
  # server on 4444
  )" << prog << R"( --mode server --server-cert server.pem --server-key server.key --server-ca ca.pem --tun-ip 10.0.0.1/24

  # client to 1.2.3.4:4444
  )" << prog << R"( --mode client --remote 1.2.3.4:4444 --client-ca ca.pem --no-client-verify-cert --tun-ip 10.0.0.2/24

Options:
  -m,--mode {server|client|bridge}   Working mode (default server)
  -p,--port PORT                     Listen port (server/bridge)
  -r,--remote IP:PORT                Remote DTLS server (client/bridge)
  --server-ca FILE                   Server CA PEM
  --server-cert FILE                 Server Certificate PEM
  --server-key FILE                  Server Private key PEM
  --client-ca FILE                   Client CA PEM
  --client-cert FILE                 Client Certificate PEM
  --client-key FILE                  Client Private key PEM
  --tun  NAME                        TUN interface name (bridge)
  --mtu BYTES                        MTU for TUN (default 1420)
  -t,--idle SECS                     Idle timeout (default 120)
  -v,--verbose                       Verbose log
  -i,--tun-ip                        TUN Interface IP address with netmask (example: 10.0.0.1/24)
  -d,--daemon                        Run as daemon
  -h,--help                          Show this help
  --no-server-verify-cert             Server will not verify clients certificates (default: veryfing)
  --no-client-verify-cert             Client will not verify servers certificates (default: veryfing)
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
        {"server-ca", required_argument, 0, 0},
        {"server-cert", required_argument, 0, 0},
        {"server-key", required_argument, 0, 0},
        {"client-ca", required_argument, 0, 0},
        {"client-cert", required_argument, 0, 0},
        {"client-key", required_argument, 0, 0},
        {"tun", required_argument, 0, 0},
        {"mtu", required_argument, 0, 0},
        {"idle", required_argument, 0, 't'},
        {"tun-ip", required_argument, 0, 'i'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {"daemon", no_argument, 0, 'd'},
        {"no-server-verify-cert", no_argument, 0, 0},
        {"no-client-verify-cert", no_argument, 0, 0},
        {0, 0, 0, 0}};
    int c, idx;
    while ((c = getopt_long(argc, argv, "m:p:r:t:i:vhd", long_opts, &idx)) != -1) {
        switch (c) {
        case 'm':
            if (strcasecmp(optarg, "server") == 0) {
                opt.mode = arg_opts_t::mode_t::SERVER;
            } else if (strcasecmp(optarg, "client") == 0) {
                opt.mode = arg_opts_t::mode_t::CLIENT;
            } else if (strcasecmp(optarg, "bridge") == 0) {
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
            if (std::string{long_opts[idx].name} == "server-ca") {
                opt.server_ca_file = optarg;
            } else if (std::string{long_opts[idx].name} == "server-cert") {
                opt.server_cert_file = optarg;
            } else if (std::string{long_opts[idx].name} == "server-key") {
                opt.server_key_file = optarg;
            } else if (std::string{long_opts[idx].name} == "client-ca") {
                opt.client_ca_file = optarg;
            } else if (std::string{long_opts[idx].name} == "client-cert") {
                opt.client_cert_file = optarg;
            } else if (std::string{long_opts[idx].name} == "client-key") {
                opt.client_key_file = optarg;
            } else if (std::string{long_opts[idx].name} == "tun") {
                opt.tun_name = optarg;
            } else if (std::string{long_opts[idx].name} == "mtu") {
                opt.mtu = std::stoi(optarg);
            } else if (std::string{long_opts[idx].name} == "no-server-verify-cert") {
                opt.server_verify_peer = false;
            } else if (std::string{long_opts[idx].name} == "no-client-verify-cert") {
                opt.client_verify_peer = false;
            }
            break;
        case 'h':
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

        if (opt.client_ca_file.empty()) {
            std::cerr << "CA required\n";
            arg_usage(argv[0]);
            std::exit(1);
        }

        if (opt.client_verify_peer) {
            if (opt.server_cert_file.empty()) {
                std::cerr << "Client side certificate required\n";
                arg_usage(argv[0]);
                std::exit(1);
            }
            
            if (opt.server_key_file.empty()) {
                std::cerr << "Client side key required\n";
                arg_usage(argv[0]);
                std::exit(1);
            }
        }
    }

    if (opt.mode != arg_opts_t::mode_t::CLIENT) {
        if (opt.server_cert_file.empty()) {
            std::cerr << "Server side certificate required\n";
            arg_usage(argv[0]);
            std::exit(1);
        }
        
        if (opt.server_key_file.empty()) {
            std::cerr << "Server side key required\n";
            arg_usage(argv[0]);
            std::exit(1);
        }

        if (opt.server_verify_peer) {
            if (opt.server_ca_file.empty()) {
                std::cerr << "Server verifies clients certificates, CA is required\n";
                arg_usage(argv[0]);
                std::exit(1);
            }
        }
    }

    return opt;
}
