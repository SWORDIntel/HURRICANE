/*
 * Proxy Mode Implementation
 * UDP/TCP relay for constrained environments
 */

#include "proxy.h"
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

static proxy_config_t g_proxy_config = {0};
static proxy_mapping_t g_udp_mappings[MAX_PROXY_MAPPINGS] = {0};
static proxy_mapping_t g_tcp_mappings[MAX_PROXY_MAPPINGS] = {0};
static int g_udp_mapping_count = 0;
static int g_tcp_mapping_count = 0;
static bool g_proxy_initialized = false;

int proxy_init(const proxy_config_t *config) {
    if (g_proxy_initialized) {
        return 0;
    }

    if (!config) {
        return -1;
    }

    memcpy(&g_proxy_config, config, sizeof(proxy_config_t));

    log_info("Initializing proxy mode");
    log_info("  UDP base port: %d", config->udp_base_port);
    log_info("  TCP base port: %d", config->tcp_base_port);

    g_proxy_initialized = true;
    return 0;
}

int proxy_add_udp_mapping(uint16_t local_port, const struct in6_addr *remote_addr,
                         uint16_t remote_port, const char *description) {
    if (!g_proxy_initialized || g_udp_mapping_count >= MAX_PROXY_MAPPINGS) {
        return -1;
    }

    proxy_mapping_t *mapping = &g_udp_mappings[g_udp_mapping_count];
    memset(mapping, 0, sizeof(*mapping));

    mapping->local_port = local_port;
    mapping->remote_port = remote_port;
    memcpy(&mapping->remote_addr, remote_addr, sizeof(struct in6_addr));
    snprintf(mapping->description, sizeof(mapping->description), "%s", description);
    mapping->active = true;

    /* Create UDP socket for listening */
    mapping->socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (mapping->socket_fd < 0) {
        log_error("Failed to create UDP socket: %s", strerror(errno));
        return -1;
    }

    /* Set non-blocking */
    int flags = fcntl(mapping->socket_fd, F_GETFL, 0);
    fcntl(mapping->socket_fd, F_SETFL, flags | O_NONBLOCK);

    /* Bind to local port */
    struct sockaddr_in local_addr = {0};
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    local_addr.sin_port = htons(local_port);

    if (bind(mapping->socket_fd, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        log_error("Failed to bind UDP port %d: %s", local_port, strerror(errno));
        close(mapping->socket_fd);
        mapping->socket_fd = -1;
        return -1;
    }

    g_udp_mapping_count++;

    char addr_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, remote_addr, addr_str, sizeof(addr_str));
    log_info("Added UDP proxy: 127.0.0.1:%d -> [%s]:%d (%s)",
             local_port, addr_str, remote_port, description);

    return 0;
}

int proxy_add_tcp_mapping(uint16_t local_port, const struct in6_addr *remote_addr,
                         uint16_t remote_port, const char *description) {
    if (!g_proxy_initialized || g_tcp_mapping_count >= MAX_PROXY_MAPPINGS) {
        return -1;
    }

    proxy_mapping_t *mapping = &g_tcp_mappings[g_tcp_mapping_count];
    memset(mapping, 0, sizeof(*mapping));

    mapping->local_port = local_port;
    mapping->remote_port = remote_port;
    memcpy(&mapping->remote_addr, remote_addr, sizeof(struct in6_addr));
    snprintf(mapping->description, sizeof(mapping->description), "%s", description);
    mapping->active = true;

    /* Create TCP socket for listening */
    mapping->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (mapping->socket_fd < 0) {
        log_error("Failed to create TCP socket: %s", strerror(errno));
        return -1;
    }

    /* Set non-blocking and reuse address */
    int flags = fcntl(mapping->socket_fd, F_GETFL, 0);
    fcntl(mapping->socket_fd, F_SETFL, flags | O_NONBLOCK);

    int opt = 1;
    setsockopt(mapping->socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* Bind to local port */
    struct sockaddr_in local_addr = {0};
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    local_addr.sin_port = htons(local_port);

    if (bind(mapping->socket_fd, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        log_error("Failed to bind TCP port %d: %s", local_port, strerror(errno));
        close(mapping->socket_fd);
        mapping->socket_fd = -1;
        return -1;
    }

    /* Listen for connections */
    if (listen(mapping->socket_fd, 10) < 0) {
        log_error("Failed to listen on TCP port %d: %s", local_port, strerror(errno));
        close(mapping->socket_fd);
        mapping->socket_fd = -1;
        return -1;
    }

    g_tcp_mapping_count++;

    char addr_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, remote_addr, addr_str, sizeof(addr_str));
    log_info("Added TCP proxy: 127.0.0.1:%d -> [%s]:%d (%s)",
             local_port, addr_str, remote_port, description);

    return 0;
}

int proxy_remove_mapping(uint16_t local_port, proxy_mode_t mode) {
    if (!g_proxy_initialized) {
        return -1;
    }

    proxy_mapping_t *mappings = (mode == PROXY_MODE_UDP) ? g_udp_mappings : g_tcp_mappings;
    int *count = (mode == PROXY_MODE_UDP) ? &g_udp_mapping_count : &g_tcp_mapping_count;

    for (int i = 0; i < *count; i++) {
        if (mappings[i].local_port == local_port && mappings[i].active) {
            mappings[i].active = false;
            log_info("Removed %s proxy mapping for port %d",
                    (mode == PROXY_MODE_UDP) ? "UDP" : "TCP", local_port);
            return 0;
        }
    }

    return -1;
}

int proxy_process(void) {
    if (!g_proxy_initialized) {
        return 0;
    }

    char buffer[65536];  /* Maximum UDP/TCP packet size */

    /* Process UDP mappings */
    for (int i = 0; i < g_udp_mapping_count; i++) {
        proxy_mapping_t *mapping = &g_udp_mappings[i];
        if (!mapping->active || mapping->socket_fd < 0) {
            continue;
        }

        /* Receive from local UDP port */
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        ssize_t recv_len = recvfrom(mapping->socket_fd, buffer, sizeof(buffer), 0,
                                     (struct sockaddr*)&client_addr, &client_len);

        if (recv_len > 0) {
            /* Create IPv6 socket for forwarding */
            int fwd_sock = socket(AF_INET6, SOCK_DGRAM, 0);
            if (fwd_sock >= 0) {
                struct sockaddr_in6 remote_addr = {0};
                remote_addr.sin6_family = AF_INET6;
                remote_addr.sin6_port = htons(mapping->remote_port);
                memcpy(&remote_addr.sin6_addr, &mapping->remote_addr, sizeof(struct in6_addr));

                /* Forward to remote IPv6 address */
                ssize_t sent_len = sendto(fwd_sock, buffer, recv_len, 0,
                                          (struct sockaddr*)&remote_addr, sizeof(remote_addr));

                if (sent_len > 0) {
                    mapping->tx_bytes += sent_len;
                }

                /* Receive response (non-blocking) */
                struct timeval tv = {0, 100000};  /* 100ms timeout */
                setsockopt(fwd_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

                struct sockaddr_in6 resp_addr;
                socklen_t resp_len = sizeof(resp_addr);
                ssize_t resp_recv = recvfrom(fwd_sock, buffer, sizeof(buffer), 0,
                                              (struct sockaddr*)&resp_addr, &resp_len);

                if (resp_recv > 0) {
                    /* Send response back to original client */
                    sendto(mapping->socket_fd, buffer, resp_recv, 0,
                           (struct sockaddr*)&client_addr, client_len);
                    mapping->rx_bytes += resp_recv;
                }

                close(fwd_sock);
            }
        }
    }

    /* Process TCP mappings - simplified for non-blocking operation */
    for (int i = 0; i < g_tcp_mapping_count; i++) {
        proxy_mapping_t *mapping = &g_tcp_mappings[i];
        if (!mapping->active || mapping->socket_fd < 0) {
            continue;
        }

        /* Accept new connections (non-blocking) */
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(mapping->socket_fd, (struct sockaddr*)&client_addr, &client_len);

        if (client_fd >= 0) {
            /* Create IPv6 connection to remote */
            int remote_fd = socket(AF_INET6, SOCK_STREAM, 0);
            if (remote_fd >= 0) {
                struct sockaddr_in6 remote_addr = {0};
                remote_addr.sin6_family = AF_INET6;
                remote_addr.sin6_port = htons(mapping->remote_port);
                memcpy(&remote_addr.sin6_addr, &mapping->remote_addr, sizeof(struct in6_addr));

                /* Set non-blocking for connect */
                int flags = fcntl(remote_fd, F_GETFL, 0);
                fcntl(remote_fd, F_SETFL, flags | O_NONBLOCK);

                connect(remote_fd, (struct sockaddr*)&remote_addr, sizeof(remote_addr));

                /* Simple bidirectional relay (non-blocking) */
                /* Note: Production implementation would use epoll/select for efficiency */
                ssize_t client_recv, remote_recv;

                /* Forward client -> remote */
                client_recv = recv(client_fd, buffer, sizeof(buffer), MSG_DONTWAIT);
                if (client_recv > 0) {
                    ssize_t sent = send(remote_fd, buffer, client_recv, MSG_DONTWAIT);
                    if (sent > 0) mapping->tx_bytes += sent;
                }

                /* Forward remote -> client */
                remote_recv = recv(remote_fd, buffer, sizeof(buffer), MSG_DONTWAIT);
                if (remote_recv > 0) {
                    ssize_t sent = send(client_fd, buffer, remote_recv, MSG_DONTWAIT);
                    if (sent > 0) mapping->rx_bytes += sent;
                }

                close(remote_fd);
            }
            close(client_fd);
        }
    }

    return 0;
}

int proxy_get_stats(int *active_mappings, uint64_t *total_tx, uint64_t *total_rx) {
    if (!g_proxy_initialized) {
        return -1;
    }

    int active = 0;
    uint64_t tx = 0;
    uint64_t rx = 0;

    for (int i = 0; i < g_udp_mapping_count; i++) {
        if (g_udp_mappings[i].active) {
            active++;
            tx += g_udp_mappings[i].tx_bytes;
            rx += g_udp_mappings[i].rx_bytes;
        }
    }

    for (int i = 0; i < g_tcp_mapping_count; i++) {
        if (g_tcp_mappings[i].active) {
            active++;
            tx += g_tcp_mappings[i].tx_bytes;
            rx += g_tcp_mappings[i].rx_bytes;
        }
    }

    if (active_mappings) *active_mappings = active;
    if (total_tx) *total_tx = tx;
    if (total_rx) *total_rx = rx;

    return 0;
}

void proxy_cleanup(void) {
    if (!g_proxy_initialized) {
        return;
    }

    log_info("Cleaning up proxy mode");

    /* Close all UDP sockets */
    for (int i = 0; i < g_udp_mapping_count; i++) {
        if (g_udp_mappings[i].socket_fd >= 0) {
            close(g_udp_mappings[i].socket_fd);
            g_udp_mappings[i].socket_fd = -1;
        }
    }

    /* Close all TCP sockets */
    for (int i = 0; i < g_tcp_mapping_count; i++) {
        if (g_tcp_mappings[i].socket_fd >= 0) {
            close(g_tcp_mappings[i].socket_fd);
            g_tcp_mappings[i].socket_fd = -1;
        }
    }

    /* Clear mappings */
    memset(g_udp_mappings, 0, sizeof(g_udp_mappings));
    memset(g_tcp_mappings, 0, sizeof(g_tcp_mappings));
    g_udp_mapping_count = 0;
    g_tcp_mapping_count = 0;

    g_proxy_initialized = false;
}
