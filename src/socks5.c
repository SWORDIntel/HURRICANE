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

/* Handle SOCKS5 connection */
static void socks5_handle_connection(int client_fd) {
    uint8_t buffer[512];
    ssize_t n;

    /* 1. Version negotiation */
    n = recv(client_fd, buffer, 2, 0);
    if (n < 2 || buffer[0] != 0x05) {  /* SOCKS version 5 */
        log_debug("SOCKS5: Invalid version");
        close(client_fd);
        return;
    }

    uint8_t nmethods = buffer[1];
    n = recv(client_fd, buffer, nmethods, 0);
    if (n < nmethods) {
        log_debug("SOCKS5: Failed to read auth methods");
        close(client_fd);
        return;
    }

    /* Accept NO AUTHENTICATION (0x00) */
    uint8_t response[2] = {0x05, 0x00};  /* Version 5, NO AUTH */
    send(client_fd, response, 2, 0);

    /* 2. Read CONNECT request */
    n = recv(client_fd, buffer, 4, 0);
    if (n < 4 || buffer[0] != 0x05 || buffer[1] != 0x01) {  /* CONNECT command */
        log_debug("SOCKS5: Invalid request");
        uint8_t error[2] = {0x05, 0x07};  /* Command not supported */
        send(client_fd, error, 2, 0);
        close(client_fd);
        return;
    }

    /* Parse address type */
    uint8_t atyp = buffer[3];
    char target_host[256] = {0};
    uint16_t target_port = 0;
    int target_fd = -1;

    if (atyp == 0x01) {  /* IPv4 */
        struct in_addr ipv4_addr;
        recv(client_fd, &ipv4_addr, 4, 0);
        recv(client_fd, &target_port, 2, 0);
        target_port = ntohs(target_port);

        inet_ntop(AF_INET, &ipv4_addr, target_host, sizeof(target_host));

        /* Create IPv4 connection */
        target_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (target_fd >= 0) {
            struct sockaddr_in addr = {0};
            addr.sin_family = AF_INET;
            addr.sin_addr = ipv4_addr;
            addr.sin_port = htons(target_port);
            if (connect(target_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
                close(target_fd);
                target_fd = -1;
            } else {
                g_socks5_stats.ipv4_connections++;
            }
        }

    } else if (atyp == 0x04) {  /* IPv6 */
        struct in6_addr ipv6_addr;
        recv(client_fd, &ipv6_addr, 16, 0);
        recv(client_fd, &target_port, 2, 0);
        target_port = ntohs(target_port);

        inet_ntop(AF_INET6, &ipv6_addr, target_host, sizeof(target_host));

        /* Create IPv6 connection */
        target_fd = socket(AF_INET6, SOCK_STREAM, 0);
        if (target_fd >= 0) {
            struct sockaddr_in6 addr = {0};
            addr.sin6_family = AF_INET6;
            addr.sin6_addr = ipv6_addr;
            addr.sin6_port = htons(target_port);
            if (connect(target_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
                close(target_fd);
                target_fd = -1;
            } else {
                g_socks5_stats.ipv6_connections++;
            }
        }

    } else if (atyp == 0x03) {  /* Domain name */
        uint8_t len;
        recv(client_fd, &len, 1, 0);
        recv(client_fd, target_host, len, 0);
        target_host[len] = '\0';
        recv(client_fd, &target_port, 2, 0);
        target_port = ntohs(target_port);

        /* Try IPv6 first if preferred, fallback to IPv4 */
        if (g_socks5_config.prefer_ipv6) {
            target_fd = socket(AF_INET6, SOCK_STREAM, 0);
            /* Domain resolution would go here - simplified for now */
            if (target_fd >= 0) {
                g_socks5_stats.ipv6_connections++;
            }
        }

        if (target_fd < 0) {
            target_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (target_fd >= 0) {
                g_socks5_stats.ipv4_connections++;
            }
        }
    }

    /* 3. Send connection response */
    if (target_fd < 0) {
        /* Connection failed */
        uint8_t reply[10] = {0x05, 0x05, 0x00, 0x01, 0,0,0,0, 0,0};  /* Host unreachable */
        send(client_fd, reply, 10, 0);
        close(client_fd);
        return;
    }

    /* Connection succeeded */
    uint8_t reply[10] = {0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0};  /* Success */
    send(client_fd, reply, 10, 0);

    g_socks5_stats.active_connections++;

    /* 4. Relay traffic bidirectionally (simplified non-blocking) */
    fcntl(client_fd, F_SETFL, O_NONBLOCK);
    fcntl(target_fd, F_SETFL, O_NONBLOCK);

    char relay_buffer[8192];
    ssize_t client_recv, target_recv;

    /* Forward client -> target */
    client_recv = recv(client_fd, relay_buffer, sizeof(relay_buffer), MSG_DONTWAIT);
    if (client_recv > 0) {
        ssize_t sent = send(target_fd, relay_buffer, client_recv, MSG_DONTWAIT);
        if (sent > 0) g_socks5_stats.tx_bytes += sent;
    }

    /* Forward target -> client */
    target_recv = recv(target_fd, relay_buffer, sizeof(relay_buffer), MSG_DONTWAIT);
    if (target_recv > 0) {
        ssize_t sent = send(client_fd, relay_buffer, target_recv, MSG_DONTWAIT);
        if (sent > 0) g_socks5_stats.rx_bytes += sent;
    }

    g_socks5_stats.active_connections--;
    close(target_fd);
    close(client_fd);
}

int socks5_process(void) {
    if (g_socks5_sockfd < 0) {
        return 0;
    }

    /* Accept new connections (non-blocking) */
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    int client_fd = accept(g_socks5_sockfd, (struct sockaddr*)&client_addr, &client_len);
    if (client_fd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            log_error("SOCKS5 accept() failed: %s", strerror(errno));
        }
        return 0;
    }

    /* Handle SOCKS5 connection */
    log_debug("SOCKS5 connection from %s", inet_ntoa(client_addr.sin_addr));
    g_socks5_stats.total_connections++;

    /* Note: Production implementation would use epoll/threads for concurrent connections */
    socks5_handle_connection(client_fd);

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
