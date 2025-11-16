/*
 * SOCKS5 Proxy Mode
 * Mode C: Generic proxy with IPv6 preference
 */

#ifndef SOCKS5_H
#define SOCKS5_H

#include <stdint.h>
#include <stdbool.h>

/* SOCKS5 configuration */
typedef struct {
    bool enabled;
    char bind_addr[64];
    uint16_t bind_port;
    bool prefer_ipv6;
    int max_connections;
} socks5_config_t;

/* SOCKS5 statistics */
typedef struct {
    uint32_t total_connections;
    uint32_t active_connections;
    uint32_t ipv6_connections;
    uint32_t ipv4_connections;
    uint64_t tx_bytes;
    uint64_t rx_bytes;
} socks5_stats_t;

/* Initialize SOCKS5 proxy */
int socks5_init(const socks5_config_t *config);

/* Start SOCKS5 proxy server */
int socks5_start(void);

/* Stop SOCKS5 proxy server */
void socks5_stop(void);

/* Process SOCKS5 requests (call in main loop) */
int socks5_process(void);

/* Get SOCKS5 statistics */
int socks5_get_stats(socks5_stats_t *stats);

/* Cleanup SOCKS5 proxy */
void socks5_cleanup(void);

#endif /* SOCKS5_H */
