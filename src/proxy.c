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
    /* Simple implementation - in production would need proper event loop */
    /* For now, this is a placeholder that returns 0 */
    /* Full implementation would:
     * 1. Accept connections on all TCP proxy ports
     * 2. Read UDP datagrams on all UDP proxy ports
     * 3. Forward to remote IPv6 addresses
     * 4. Handle bidirectional traffic
     */
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

    /* Close all proxy sockets and cleanup mappings */
    memset(g_udp_mappings, 0, sizeof(g_udp_mappings));
    memset(g_tcp_mappings, 0, sizeof(g_tcp_mappings));
    g_udp_mapping_count = 0;
    g_tcp_mapping_count = 0;

    g_proxy_initialized = false;
}
