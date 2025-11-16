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

static int tunnel_create_wireguard(tunnel_t *tunnel) {
    char cmd[512];
    const tunnel_config_t *cfg = &tunnel->config;

    log_info("Creating WireGuard tunnel: %s", cfg->name);

    /* Check if wg-quick is available */
    if (system("which wg-quick >/dev/null 2>&1") != 0) {
        log_error("wg-quick not found - please install wireguard-tools");
        return -1;
    }

    /* Bring up WireGuard interface using wg-quick */
    snprintf(cmd, sizeof(cmd), "wg-quick up %s 2>&1", cfg->iface);
    if (exec_cmd(cmd) != 0) {
        log_error("Failed to bring up WireGuard interface %s", cfg->iface);
        log_info("Ensure /etc/wireguard/%s.conf exists", cfg->iface);
        return -1;
    }

    /* Parse IPv6 address from interface */
    if (strlen(cfg->v6_prefix) > 0) {
        if (inet_pton(AF_INET6, cfg->v6_prefix, &tunnel->v6_addr) != 1) {
            log_error("Invalid IPv6 address: %s", cfg->v6_prefix);
            return -1;
        }
    }

    tunnel->state = TUNNEL_STATE_UP;
    tunnel->last_check = time(NULL);
    log_info("WireGuard tunnel %s is UP", cfg->name);

    return 0;
}

static int tunnel_destroy_wireguard(tunnel_t *tunnel) {
    char cmd[512];
    const tunnel_config_t *cfg = &tunnel->config;

    log_info("Destroying WireGuard tunnel: %s", cfg->name);

    snprintf(cmd, sizeof(cmd), "wg-quick down %s 2>&1", cfg->iface);
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
            return tunnel_create_wireguard(tunnel);
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
            return tunnel_destroy_wireguard(tunnel);
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

int tunnel_calculate_health(tunnel_t *tunnel) {
    if (!tunnel || tunnel->state != TUNNEL_STATE_UP) {
        return 0;
    }

    int score = 100;

    /* Check reachability (-50 points if unreachable) */
    if (!tunnel->reachable) {
        score -= 50;
    }

    /* Latency scoring (0-50 points based on latency) */
    if (tunnel->latency_ms > 0) {
        if (tunnel->latency_ms < 50) {
            /* Excellent: 50 points */
        } else if (tunnel->latency_ms < 100) {
            score -= 10;  /* Good: 40 points */
        } else if (tunnel->latency_ms < 200) {
            score -= 25;  /* Fair: 25 points */
        } else if (tunnel->latency_ms < 500) {
            score -= 40;  /* Poor: 10 points */
        } else {
            score -= 50;  /* Very poor: 0 points */
        }
    }

    /* Ensure score is in valid range */
    if (score < 0) score = 0;
    if (score > 100) score = 100;

    tunnel->health_score = score;
    return score;
}

tunnel_t* tunnel_select_best(tunnel_t *tunnels, int tunnel_count) {
    if (!tunnels || tunnel_count <= 0) {
        return NULL;
    }

    tunnel_t *best = NULL;
    int best_score = -1;

    for (int i = 0; i < tunnel_count; i++) {
        tunnel_t *t = &tunnels[i];

        /* Skip disabled or down tunnels */
        if (!t->config.enabled || t->state != TUNNEL_STATE_UP) {
            continue;
        }

        /* Calculate current health score */
        int score = tunnel_calculate_health(t);

        /* Apply priority bonus (higher priority = lower number = more bonus) */
        /* Priority 0 gets +20 points, priority 1 gets +15, etc. */
        int priority_bonus = (5 - t->priority) * 5;
        if (priority_bonus < 0) priority_bonus = 0;
        score += priority_bonus;

        if (score > best_score) {
            best_score = score;
            best = t;
        }
    }

    return best;
}

int tunnel_auto_failover(tunnel_t *tunnels, int tunnel_count) {
    if (!tunnels || tunnel_count <= 0) {
        return -1;
    }

    /* Find current primary tunnel */
    tunnel_t *current_primary = NULL;
    for (int i = 0; i < tunnel_count; i++) {
        if (tunnels[i].is_primary) {
            current_primary = &tunnels[i];
            break;
        }
    }

    /* If no primary set, select best tunnel */
    if (!current_primary) {
        tunnel_t *best = tunnel_select_best(tunnels, tunnel_count);
        if (best) {
            best->is_primary = true;
            log_info("Selected primary tunnel: %s (health: %d)",
                    best->config.name, best->health_score);
            return 0;
        }
        return -1;
    }

    /* Check if current primary is healthy */
    tunnel_calculate_health(current_primary);

    /* Failover threshold: switch if health < 30 or tunnel is down */
    bool need_failover = false;
    if (current_primary->state != TUNNEL_STATE_UP) {
        log_warn("Primary tunnel %s is DOWN", current_primary->config.name);
        need_failover = true;
    } else if (current_primary->health_score < 30) {
        log_warn("Primary tunnel %s health degraded: %d/100",
                current_primary->config.name, current_primary->health_score);
        need_failover = true;
    }

    if (need_failover) {
        /* Find best alternative tunnel */
        tunnel_t *best = NULL;
        int best_score = -1;

        for (int i = 0; i < tunnel_count; i++) {
            tunnel_t *t = &tunnels[i];

            /* Skip current primary and disabled tunnels */
            if (t == current_primary || !t->config.enabled) {
                continue;
            }

            /* Skip down tunnels */
            if (t->state != TUNNEL_STATE_UP) {
                continue;
            }

            int score = tunnel_calculate_health(t);

            /* Only failover if alternative is significantly better */
            if (score > best_score && score >= 50) {
                best_score = score;
                best = t;
            }
        }

        if (best) {
            log_info("Failing over from %s to %s (health: %d -> %d)",
                    current_primary->config.name, best->config.name,
                    current_primary->health_score, best->health_score);

            current_primary->is_primary = false;
            best->is_primary = true;

            /* Update routing if needed */
            /* TODO: Update default route to use new primary tunnel */

            return 0;
        } else {
            log_error("No healthy backup tunnel available for failover");
            return -1;
        }
    }

    return 0;
}

void tunnel_cleanup(void) {
    log_info("Cleaning up tunnel subsystem");
}
