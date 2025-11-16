/*
 * Proxy Mode (UDP/TCP Relay)
 * Mode B: Local proxy for constrained environments
 */

#ifndef PROXY_H
#define PROXY_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

#define MAX_PROXY_MAPPINGS 256

/* Proxy mapping */
typedef struct {
    uint16_t local_port;
    uint16_t remote_port;
    struct in6_addr remote_addr;
    char description[128];
    bool active;
    uint64_t tx_bytes;
    uint64_t rx_bytes;
} proxy_mapping_t;

/* Proxy mode types */
typedef enum {
    PROXY_MODE_UDP,
    PROXY_MODE_TCP
} proxy_mode_t;

/* Proxy configuration */
typedef struct {
    bool enabled;
    uint16_t udp_base_port;
    uint16_t tcp_base_port;
    int max_connections;
} proxy_config_t;

/* Initialize proxy subsystem */
int proxy_init(const proxy_config_t *config);

/* Create UDP proxy mapping */
int proxy_add_udp_mapping(uint16_t local_port, const struct in6_addr *remote_addr,
                         uint16_t remote_port, const char *description);

/* Create TCP proxy mapping */
int proxy_add_tcp_mapping(uint16_t local_port, const struct in6_addr *remote_addr,
                         uint16_t remote_port, const char *description);

/* Remove proxy mapping */
int proxy_remove_mapping(uint16_t local_port, proxy_mode_t mode);

/* Process proxy requests (call in main loop) */
int proxy_process(void);

/* Get proxy statistics */
int proxy_get_stats(int *active_mappings, uint64_t *total_tx, uint64_t *total_rx);

/* Cleanup proxy subsystem */
void proxy_cleanup(void);

#endif /* PROXY_H */
