#include <spdlog/spdlog.h>
#include <sys/stat.h>

#include <chrono>
#include <condition_variable>
#include <csignal>
#include <iostream>
#include <memory>
#include <mutex>
#include <thread>

#include "arg_parse.h"
#include "dtls_cl.h"
#include "dtls_srv.h"
#include "tun.h"
#include "udp_srv.h"

static std::mutex mu_;
static std::condition_variable running_;

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

struct bridge_ctx_t {
    dtls_server_t *srv{nullptr};
    dtls_client_t *cli{nullptr};
    udp_server_t *udp_cli{nullptr};
    udp_server_t *udp_srv{nullptr};
    tun_if_t *tun{nullptr};
};

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

static void kill_app(int sig)
{
    running_.notify_all();
}

int main(int argc, char **argv)
{
    arg_opts_t cfg = parse_args(argc, argv);

    if (cfg.verbose) {
        spdlog::set_level(spdlog::level::debug);
    } else {
        spdlog::set_level(spdlog::level::info);
    }

    spdlog::set_pattern("[%H:%M:%S:%f] [%^%l%$] [tid:%t] %v");

    signal(SIGINT, kill_app);
    signal(SIGQUIT, kill_app);
    signal(SIGTERM, kill_app);

    if (cfg.daemon) {
        daemonize();
    }

    auto tun = std::make_shared<tun_if_t>(cfg.tun_name, tun_rx_cb, cfg.mtu, cfg.tun_ip, cfg.tun_cidr);

    std::shared_ptr<dtls_server_t> srv;
    std::shared_ptr<udp_server_t> udp_srv;
    std::shared_ptr<dtls_client_t> cli;
    std::shared_ptr<udp_server_t> udp_cl;

    bridge_ctx_t ctx = {
        .tun = tun.get(),
    };

    if (cfg.mode != arg_opts_t::mode_t::CLIENT) {
        udp_srv = std::make_shared<udp_server_t>(cfg.listen_port, [](const io_t::endpoint_t &from, const uint8_t *d, size_t n, io_t &self) {
            dtls_server_t *srv = self.get_user_data<dtls_server_t>();
            if (srv != nullptr) {
                srv->handle_datagram(from, d, n);
            }
        });

        srv = std::make_shared<dtls_server_t>(
            [&udp_srv](const io_t::endpoint_t &to,
                       const uint8_t *d, size_t n) {
                if (udp_srv.get()) {
                    udp_srv->write(to, d, n);
                }
            },
            cfg.server_ca_file, cfg.server_cert_file, cfg.server_key_file,
            srv_app_cb,
            cfg.mtu,
            std::chrono::seconds(cfg.idle_sec));

        ctx.srv = srv.get();
        ctx.udp_srv = udp_srv.get();

        udp_srv->set_user_data(srv.get());
        srv->set_user_data(&ctx);
        srv->set_verify_peer(cfg.server_verify_peer);
        srv->enable_debug();
    }

    if (cfg.mode != arg_opts_t::mode_t::SERVER) {
        io_t::endpoint_t remote{cfg.remote_ip, cfg.remote_port};

        udp_cl = std::make_shared<udp_server_t>(0, [](const io_t::endpoint_t &from, const uint8_t *d, size_t n, io_t &self) {
            dtls_client_t *cl = self.get_user_data<dtls_client_t>();
            if (cl != nullptr) {
                cl->handle_datagram(from, d, n);
            }
        });

        cli = std::make_shared<dtls_client_t>(
            [&udp_cl](const io_t::endpoint_t &to,
                      const uint8_t *d, size_t n) {
                if (udp_cl.get()) {
                    udp_cl->write(to, d, n);
                }
            },
            remote,
            cfg.client_ca_file, cfg.client_cert_file, cfg.client_key_file,
            cli_app_cb,
            cfg.mtu,
            std::chrono::seconds(cfg.idle_sec));

        ctx.cli = cli.get();
        ctx.udp_cli = udp_cl.get();

        udp_cl->set_user_data(cli.get());
        cli->set_user_data(&ctx);
        cli->set_verify_peer(cfg.client_verify_peer);
        cli->enable_debug();
    }

    tun->set_user_data(&ctx);

    spdlog::info("Running in {} mode", (cfg.mode == arg_opts_t::mode_t::SERVER ? "server" : cfg.mode == arg_opts_t::mode_t::CLIENT ? "client"
                                                                                                                                   : "bridge"));

    std::unique_lock<std::mutex> lk{mu_};
    running_.wait(lk);
    spdlog::warn("Catch SIGKILL/SIGINT signal. Exiting..");
    tun.reset();

    if (cli) {
        cli.reset();
    }

    if (srv) {
        srv.reset();
    }

    if (udp_cl) {
        udp_cl.reset();
    }

    if (udp_srv) {
        udp_srv.reset();
    }

    return 0;
}
