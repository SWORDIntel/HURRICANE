/*
 * Tunnel management implementation
 * Handles HE 6in4, WireGuard, and external tunnels
 */

#include "tunnel.h"
#include "log.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tunnel.h>

int tunnel_init(void) {
    log_info("Initializing tunnel subsystem");
    return 0;
}

static int tunnel_create_he6in4(tunnel_t *tunnel) {
    char cmd[512];
    const tunnel_config_t *cfg = &tunnel->config;

    log_info("Creating HE 6in4 tunnel: %s", cfg->name);

    /* Delete interface if it exists */
    snprintf(cmd, sizeof(cmd), "ip tunnel del %s 2>/dev/null", cfg->iface);
    exec_cmd(cmd);

    /* Create sit tunnel */
    snprintf(cmd, sizeof(cmd),
        "ip tunnel add %s mode sit remote %s local %s ttl 255",
        cfg->iface, cfg->endpoint_ipv4,
        strlen(cfg->local_ipv4) > 0 ? cfg->local_ipv4 : "any");
    if (exec_cmd(cmd) != 0) {
        log_error("Failed to create tunnel interface");
        return -1;
    }

    /* Bring interface up */
    snprintf(cmd, sizeof(cmd), "ip link set %s up", cfg->iface);
    if (exec_cmd(cmd) != 0) {
        log_error("Failed to bring up tunnel interface");
        return -1;
    }

    /* Add IPv6 address */
    snprintf(cmd, sizeof(cmd), "ip -6 addr add %s/%d dev %s",
        cfg->v6_prefix, cfg->prefix_len, cfg->iface);
    if (exec_cmd(cmd) != 0) {
        log_warn("Failed to add IPv6 address (may already exist)");
    }

    /* Add default route if needed */
    snprintf(cmd, sizeof(cmd), "ip -6 route add ::/0 dev %s 2>/dev/null", cfg->iface);
    exec_cmd(cmd);  /* Non-fatal if it fails */

    /* Parse IPv6 address */
    if (inet_pton(AF_INET6, cfg->v6_prefix, &tunnel->v6_addr) != 1) {
        log_error("Invalid IPv6 address: %s", cfg->v6_prefix);
        return -1;
    }

    tunnel->state = TUNNEL_STATE_UP;
    tunnel->last_check = time(NULL);
    log_info("Tunnel %s is UP", cfg->name);

    return 0;
}

static int tunnel_destroy_he6in4(tunnel_t *tunnel) {
    char cmd[512];
    const tunnel_config_t *cfg = &tunnel->config;

    log_info("Destroying HE 6in4 tunnel: %s", cfg->name);

    snprintf(cmd, sizeof(cmd), "ip tunnel del %s", cfg->iface);
    exec_cmd(cmd);

    tunnel->state = TUNNEL_STATE_DOWN;
    return 0;
}

int tunnel_up(tunnel_t *tunnel) {
    if (!tunnel || !tunnel->config.enabled) {
        return -1;
    }

    switch (tunnel->config.type) {
        case TUNNEL_TYPE_HE_6IN4:
            return tunnel_create_he6in4(tunnel);
        case TUNNEL_TYPE_WIREGUARD:
            log_warn("WireGuard tunnel support not yet implemented");
            return -1;
        case TUNNEL_TYPE_EXTERNAL:
            log_info("External tunnel %s (assuming pre-configured)", tunnel->config.name);
            tunnel->state = TUNNEL_STATE_UP;
            return 0;
        default:
            log_error("Unknown tunnel type");
            return -1;
    }
}

int tunnel_down(tunnel_t *tunnel) {
    if (!tunnel) {
        return -1;
    }

    switch (tunnel->config.type) {
        case TUNNEL_TYPE_HE_6IN4:
            return tunnel_destroy_he6in4(tunnel);
        case TUNNEL_TYPE_WIREGUARD:
        case TUNNEL_TYPE_EXTERNAL:
            tunnel->state = TUNNEL_STATE_DOWN;
            return 0;
        default:
            return -1;
    }
}

int tunnel_check(tunnel_t *tunnel) {
    if (!tunnel || tunnel->state != TUNNEL_STATE_UP) {
        return -1;
    }

    /* Check if interface exists */
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", tunnel->config.iface);

    int ret = ioctl(sockfd, SIOCGIFFLAGS, &ifr);
    close(sockfd);

    if (ret < 0) {
        tunnel->state = TUNNEL_STATE_ERROR;
        tunnel->reachable = false;
        return -1;
    }

    /* Check if interface is up */
    if (!(ifr.ifr_flags & IFF_UP)) {
        tunnel->reachable = false;
        return -1;
    }

    tunnel->reachable = true;
    tunnel->last_check = time(NULL);
    return 0;
}

int tunnel_get_stats(tunnel_t *tunnel) {
    if (!tunnel) {
        return -1;
    }

    /* Read interface statistics from /sys/class/net */
    char path[256];
    char buf[64];

    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/rx_bytes", tunnel->config.iface);
    if (read_file_line(path, buf, sizeof(buf)) == 0) {
        tunnel->rx_bytes = atoll(buf);
    }

    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/tx_bytes", tunnel->config.iface);
    if (read_file_line(path, buf, sizeof(buf)) == 0) {
        tunnel->tx_bytes = atoll(buf);
    }

    return 0;
}

void tunnel_cleanup(void) {
    log_info("Cleaning up tunnel subsystem");
}
