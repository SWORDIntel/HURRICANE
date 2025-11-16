/*
 * HURRICANE v6-gatewayd
 * Main daemon entry point
 */

#include "v6gw.h"
#include "config.h"
#include "log.h"
#include "tunnel.h"
#include "health.h"
#include "api.h"
#include "mcp.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>

/* Global daemon context */
daemon_ctx_t g_ctx = {0};

static void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        log_info("Received signal %d, shutting down...", sig);
        g_ctx.running = false;
    } else if (sig == SIGHUP) {
        log_info("Received SIGHUP, reloading configuration...");
        /* TODO: Implement config reload */
    }
}

static void setup_signals(void) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGHUP, signal_handler);
    signal(SIGPIPE, SIG_IGN);
}

static void print_usage(const char *progname) {
    printf("HURRICANE v6-gatewayd v%s\n", VERSION);
    printf("IPv6-over-IPv4 tunnel gateway with programmatic API\n\n");
    printf("Usage: %s [options]\n\n", progname);
    printf("Options:\n");
    printf("  -c, --config FILE   Configuration file (default: /etc/v6-gatewayd.conf)\n");
    printf("  -f, --foreground    Run in foreground (don't daemonize)\n");
    printf("  -d, --debug         Enable debug logging\n");
    printf("  -v, --version       Show version information\n");
    printf("  -h, --help          Show this help message\n");
}

static int init_tunnels(void) {
    log_info("Initializing %d tunnel(s)", g_ctx.config.tunnel_count);

    for (int i = 0; i < g_ctx.config.tunnel_count; i++) {
        tunnel_t *t = &g_ctx.tunnels[i];
        t->config = g_ctx.config.tunnels[i];
        t->state = TUNNEL_STATE_DOWN;

        if (t->config.enabled) {
            log_info("Bringing up tunnel: %s", t->config.name);
            if (tunnel_up(t) == 0) {
                g_ctx.tunnel_count++;
                log_info("Tunnel %s started successfully", t->config.name);
            } else {
                log_error("Failed to start tunnel %s", t->config.name);
            }
        }
    }

    return 0;
}

static void shutdown_tunnels(void) {
    log_info("Shutting down tunnels");

    for (int i = 0; i < g_ctx.tunnel_count; i++) {
        tunnel_t *t = &g_ctx.tunnels[i];
        if (t->state == TUNNEL_STATE_UP) {
            log_info("Bringing down tunnel: %s", t->config.name);
            tunnel_down(t);
        }
    }
}

static void main_loop(void) {
    time_t last_health_check = 0;
    time_t last_stats_update = 0;

    while (g_ctx.running) {
        time_t now = time(NULL);

        /* Process API requests */
        api_process();

        /* Process MCP requests */
        mcp_process();

        /* Periodic health checks (every 30 seconds) */
        if (now - last_health_check >= 30) {
            for (int i = 0; i < g_ctx.tunnel_count; i++) {
                tunnel_check(&g_ctx.tunnels[i]);
            }
            last_health_check = now;
        }

        /* Update statistics (every 10 seconds) */
        if (now - last_stats_update >= 10) {
            for (int i = 0; i < g_ctx.tunnel_count; i++) {
                tunnel_get_stats(&g_ctx.tunnels[i]);
            }
            last_stats_update = now;
        }

        /* Sleep to avoid busy loop */
        usleep(100000);  /* 100ms */
    }
}

int main(int argc, char *argv[]) {
    const char *config_file = "/etc/v6-gatewayd.conf";
    bool foreground = false;
    bool debug = false;

    static struct option long_options[] = {
        {"config",     required_argument, 0, 'c'},
        {"foreground", no_argument,       0, 'f'},
        {"debug",      no_argument,       0, 'd'},
        {"version",    no_argument,       0, 'v'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "c:fdfvh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'c':
                config_file = optarg;
                break;
            case 'f':
                foreground = true;
                break;
            case 'd':
                debug = true;
                break;
            case 'v':
                printf("v6-gatewayd version %s\n", VERSION);
                return 0;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    /* Initialize logging */
    log_init(debug ? "debug" : "info");
    log_info("Starting HURRICANE v6-gatewayd v%s", VERSION);

    /* Parse configuration */
    if (config_parse(config_file, &g_ctx.config) != 0) {
        log_error("Failed to parse configuration file: %s", config_file);
        return 1;
    }

    /* Override log level from config */
    if (!debug) {
        log_init(g_ctx.config.log_level);
    }

    /* Validate configuration */
    if (config_validate(&g_ctx.config) != 0) {
        log_error("Invalid configuration");
        return 1;
    }

    config_print(&g_ctx.config);

    /* Check for root privileges (needed for tunnel management) */
    if (geteuid() != 0) {
        log_warn("Not running as root - tunnel management may fail");
    }

    /* Daemonize if requested */
    if (!foreground) {
        log_info("Daemonizing...");
        if (daemonize() != 0) {
            log_error("Failed to daemonize");
            return 1;
        }
    }

    /* Write PID file */
    write_pidfile("/var/run/v6-gatewayd.pid");

    /* Setup signal handlers */
    setup_signals();

    /* Initialize subsystems */
    tunnel_init();
    health_init();

    /* Initialize API server */
    api_config_t api_config = {
        .bind_addr = g_ctx.config.api_bind,
        .port = g_ctx.config.api_port,
        .backlog = 10
    };

    if (api_init(&api_config) != 0) {
        log_error("Failed to initialize API server");
        goto cleanup;
    }

    api_start();

    /* Initialize MCP server */
    mcp_config_t mcp_config = {
        .socket_path = "/var/run/v6-gatewayd-mcp.sock",
        .enabled = true
    };

    if (mcp_init(&mcp_config) == 0) {
        mcp_start();
    }

    /* Initialize tunnels */
    if (init_tunnels() != 0) {
        log_error("Failed to initialize tunnels");
        goto cleanup;
    }

    /* Main loop */
    g_ctx.running = true;
    log_info("v6-gatewayd is running");
    main_loop();

cleanup:
    log_info("Cleaning up...");

    /* Cleanup */
    shutdown_tunnels();
    api_cleanup();
    mcp_cleanup();
    health_cleanup();
    tunnel_cleanup();

    remove_pidfile("/var/run/v6-gatewayd.pid");

    log_info("v6-gatewayd stopped");
    return 0;
}
