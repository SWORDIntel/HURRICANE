/*
 * HURRICANE v6-gatewayd
 * Main header file with core definitions
 */

#ifndef V6GW_H
#define V6GW_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <time.h>

#define VERSION "1.0.0"
#define MAX_TUNNELS 16
#define MAX_PATH 256
#define MAX_LINE 1024

/* Tunnel types */
typedef enum {
    TUNNEL_TYPE_HE_6IN4,
    TUNNEL_TYPE_WIREGUARD,
    TUNNEL_TYPE_EXTERNAL
} tunnel_type_t;

/* Tunnel state */
typedef enum {
    TUNNEL_STATE_DOWN,
    TUNNEL_STATE_UP,
    TUNNEL_STATE_ERROR
} tunnel_state_t;

/* Exposure modes */
typedef enum {
    MODE_KERNEL,
    MODE_PROXY,
    MODE_SOCKS5
} exposure_mode_t;

/* Tunnel configuration */
typedef struct {
    char name[64];
    tunnel_type_t type;
    char iface[16];
    char endpoint_ipv4[INET_ADDRSTRLEN];
    char local_ipv4[INET_ADDRSTRLEN];
    char v6_prefix[INET6_ADDRSTRLEN];
    int prefix_len;
    bool enabled;
} tunnel_config_t;

/* Tunnel runtime state */
typedef struct {
    tunnel_config_t config;
    tunnel_state_t state;
    struct in6_addr v6_addr;
    time_t last_check;
    uint32_t tx_bytes;
    uint32_t rx_bytes;
    int latency_ms;
    bool reachable;
} tunnel_t;

/* Global configuration */
typedef struct {
    char log_level[16];
    char state_dir[MAX_PATH];
    int api_port;
    char api_bind[64];
    exposure_mode_t mode;
    tunnel_config_t tunnels[MAX_TUNNELS];
    int tunnel_count;
} config_t;

/* Global daemon context */
typedef struct {
    config_t config;
    tunnel_t tunnels[MAX_TUNNELS];
    int tunnel_count;
    bool running;
    int api_socket;
} daemon_ctx_t;

/* Global context */
extern daemon_ctx_t g_ctx;

#endif /* V6GW_H */
