#include "arg_parse.h"
#include "dtls_cl.h"
#include "dtls_srv.h"
#include "tun.h"
#include "udp_srv.h"

#include <chrono>
#include <iostream>
#include <memory>
#include <thread>

#include <sys/stat.h>


void print_hex(const uint8_t *buf, int sz)
{
    for (int idx = 0; idx < sz; idx += 16) {
        int idx_r = idx;
        printf("%04x: ", idx);
        for (; idx_r < sz && idx_r < idx + 16; idx_r++) {
            printf("%02x ", buf[idx_r]);
        }

        if (idx_r < idx + 16) {
            for (int idx_s = 0; idx_s < ((idx + 16) - idx_r); idx_s++)
                printf("   ");
        }

        for (idx_r = idx; idx_r < sz && idx_r < idx + 16; idx_r++) {
            printf((buf[idx_r] >= ' ' && buf[idx_r] <= '~') ? "%c" : "·", buf[idx_r]);
        }
        printf("\r\n");
    }
    printf("\r\n");
}

static void daemonize()
{
    pid_t pid = fork();
    if (pid < 0) {
        std::perror("fork");
        std::exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        /* Parent exits */
        std::exit(EXIT_SUCCESS);
    }

    if (setsid() < 0) {
        std::perror("setsid");
        std::exit(EXIT_FAILURE);
    }

    pid = fork();
    if (pid < 0) {
        std::perror("fork");
        std::exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        std::perror("Now exiting");
        std::exit(EXIT_SUCCESS);
    }

    ::umask(0);
//    ::chdir("/");

    int fd = ::open("/dev/null", O_RDWR);
    if (fd >= 0) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > STDERR_FILENO) {
            ::close(fd);
        }
    }
}

struct bridge_ctx_t
{
    dtls_server_t *srv{nullptr};
    dtls_client_t *cli{nullptr};
    udp_server_t *udp{nullptr};
    tun_if_t *tun{nullptr};
};

static void udp_rx_cb(const udp_server_t::endpoint_t &from, const uint8_t *d, size_t n, io_t &self)
{
    if (auto ctx = self.get_user_data<bridge_ctx_t>(); ctx != nullptr) {
        if (ctx->srv != nullptr) {
            ctx->srv->handle_datagram(from, d, n);
        }

        if (ctx->cli != nullptr) {
            ctx->cli->handle_datagram(from, d, n);
        }
    }
}

static void tun_rx_cb(const io_t::endpoint_t &, const uint8_t *d, size_t n, io_t &self)
{
    // printf("[TUN] > \n");
    // print_hex(d, n);

    if (auto ctx = self.get_user_data<bridge_ctx_t>(); ctx != nullptr) {
        if (ctx->srv != nullptr) {
            ctx->srv->broadcast(d, n, nullptr);
        }
        if (ctx->cli != nullptr) {
            ctx->cli->write({}, d, n);
        }
    }
}

static void srv_app_cb(const io_t::endpoint_t &from, const uint8_t *p, size_t n, io_t &self)
{
    // printf("[DTLS-SRV] %s:%d >\n", from.host.c_str(), from.port);
    // print_hex(p, n);

    if (auto ctx = self.get_user_data<bridge_ctx_t>(); ctx != nullptr) {
        if (ctx->tun != nullptr) {
            ctx->tun->write({}, p, n);
        }

        if (ctx->cli != nullptr) {
            ctx->cli->write({}, p, n);
        }

        if (ctx->srv != nullptr) {
            ctx->srv->broadcast(p, n, &from);
        }
    }
}

static void cli_app_cb(const io_t::endpoint_t &, const uint8_t *p, size_t n, io_t &self)
{
    // printf("[DTLS-CL] > \n");
    // print_hex(p, n);

    if (auto ctx = self.get_user_data<bridge_ctx_t>(); ctx != nullptr) {
        if (ctx->tun != nullptr) {
            ctx->tun->write({}, p, n);
        }

        if (ctx->srv != nullptr) {
            ctx->srv->broadcast(p, n);
        }
    }
}

int main(int argc, char **argv)
{
    arg_opts_t cfg = parse_args(argc, argv);

    if (cfg.daemon) {
        daemonize();
    }

    uint16_t bind_port = (cfg.mode == arg_opts_t::mode_t::SERVER) ? cfg.listen_port : 0;
    auto udp = std::make_shared<udp_server_t>(bind_port, udp_rx_cb);
    auto tun = std::make_shared<tun_if_t>(cfg.tun_name, tun_rx_cb, cfg.mtu, cfg.tun_ip, cfg.tun_cidr);

    std::shared_ptr<dtls_server_t> srv;
    std::shared_ptr<dtls_client_t> cli;
    bridge_ctx_t ctx = {
        .udp = udp.get(),
        .tun = tun.get(),
    };

    if (cfg.mode != arg_opts_t::mode_t::CLIENT) {
        srv = std::make_shared<dtls_server_t>(
            [&udp](const io_t::endpoint_t &to,
                   const uint8_t *d, size_t n) {
                udp->write(to, d, n);
            },
            cfg.ca_file, cfg.cert_file, cfg.key_file,
            srv_app_cb,
            cfg.mtu,
            std::chrono::seconds(cfg.idle_sec));

        ctx.srv = srv.get();
        srv->set_user_data(&ctx);
    }

    if (cfg.mode != arg_opts_t::mode_t::SERVER) {
        io_t::endpoint_t remote{cfg.remote_ip, cfg.remote_port};
        cli = std::make_shared<dtls_client_t>(
            [&udp](const io_t::endpoint_t &to,
                   const uint8_t *d, size_t n) {
                udp->write(to, d, n);
            },
            remote,
            cfg.ca_file, cfg.cert_file, cfg.key_file,
            cli_app_cb,
            cfg.mtu,
            std::chrono::seconds(cfg.idle_sec));

        ctx.cli = cli.get();
        cli->set_user_data(&ctx);
    }

    tun->set_user_data(&ctx);
    udp->set_user_data(&ctx);

    std::cerr << "Running in "
              << (cfg.mode == arg_opts_t::mode_t::SERVER ? "server" : cfg.mode == arg_opts_t::mode_t::CLIENT ? "client"
                                                                                                             : "bridge")
              << " mode\n";

    std::this_thread::sleep_for(std::chrono::hours(24));
    return 0;
}
