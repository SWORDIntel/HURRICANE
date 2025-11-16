/*
 * SOCKS5 Proxy Implementation
 * Generic proxy with IPv6 preference
 */

#include "socks5.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>

static socks5_config_t g_socks5_config = {0};
static socks5_stats_t g_socks5_stats = {0};
static int g_socks5_sockfd = -1;
static bool g_socks5_initialized = false;

int socks5_init(const socks5_config_t *config) {
    if (g_socks5_initialized) {
        return 0;
    }

    if (!config || !config->enabled) {
        log_info("SOCKS5 proxy disabled");
        return 0;
    }

    memcpy(&g_socks5_config, config, sizeof(socks5_config_t));
    memset(&g_socks5_stats, 0, sizeof(socks5_stats_t));

    log_info("Initializing SOCKS5 proxy on %s:%d",
             config->bind_addr, config->bind_port);
    log_info("  IPv6 preference: %s", config->prefer_ipv6 ? "enabled" : "disabled");

    g_socks5_initialized = true;
    return 0;
}

int socks5_start(void) {
    if (!g_socks5_initialized || !g_socks5_config.enabled) {
        return 0;
    }

    /* Create TCP socket for SOCKS5 */
    g_socks5_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_socks5_sockfd < 0) {
        log_error("Failed to create SOCKS5 socket");
        return -1;
    }

    /* Set socket options */
    int opt = 1;
    setsockopt(g_socks5_sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* Set non-blocking */
    int flags = fcntl(g_socks5_sockfd, F_GETFL, 0);
    fcntl(g_socks5_sockfd, F_SETFL, flags | O_NONBLOCK);

    /* Bind */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_socks5_config.bind_port);
    inet_pton(AF_INET, g_socks5_config.bind_addr, &addr.sin_addr);

    if (bind(g_socks5_sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        log_error("Failed to bind SOCKS5 socket: %s", strerror(errno));
        close(g_socks5_sockfd);
        g_socks5_sockfd = -1;
        return -1;
    }

    /* Listen */
    if (listen(g_socks5_sockfd, g_socks5_config.max_connections) < 0) {
        log_error("Failed to listen on SOCKS5 socket");
        close(g_socks5_sockfd);
        g_socks5_sockfd = -1;
        return -1;
    }

    log_info("SOCKS5 proxy started successfully");
    return 0;
}

void socks5_stop(void) {
    if (g_socks5_sockfd >= 0) {
        log_info("Stopping SOCKS5 proxy");
        close(g_socks5_sockfd);
        g_socks5_sockfd = -1;
    }
}

int socks5_process(void) {
    /* Placeholder implementation */
    /* Full SOCKS5 implementation would:
     * 1. Accept incoming SOCKS5 connections
     * 2. Parse SOCKS5 handshake (version, auth, etc.)
     * 3. Parse CONNECT request
     * 4. Prefer IPv6 addresses when available
     * 5. Establish connection to target
     * 6. Relay bidirectional traffic
     * 7. Update statistics
     */

    if (g_socks5_sockfd < 0) {
        return 0;
    }

    /* Try to accept connections (non-blocking) */
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    int client_fd = accept(g_socks5_sockfd, (struct sockaddr*)&client_addr, &client_len);
    if (client_fd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            log_error("SOCKS5 accept() failed: %s", strerror(errno));
        }
        return 0;
    }

    /* Got a connection - for now just close it (placeholder) */
    /* In production, this would spawn a handler thread/coroutine */
    log_debug("SOCKS5 connection from %s (not yet implemented)",
             inet_ntoa(client_addr.sin_addr));
    close(client_fd);

    g_socks5_stats.total_connections++;

    return 0;
}

int socks5_get_stats(socks5_stats_t *stats) {
    if (!g_socks5_initialized || !stats) {
        return -1;
    }

    memcpy(stats, &g_socks5_stats, sizeof(socks5_stats_t));
    return 0;
}

void socks5_cleanup(void) {
    if (!g_socks5_initialized) {
        return;
    }

    socks5_stop();

    log_info("Cleaning up SOCKS5 proxy");
    memset(&g_socks5_config, 0, sizeof(g_socks5_config));
    memset(&g_socks5_stats, 0, sizeof(g_socks5_stats));

    g_socks5_initialized = false;
}
