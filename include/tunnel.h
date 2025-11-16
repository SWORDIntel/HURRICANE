/*
 * Tunnel management (HE 6in4, WireGuard, etc.)
 */

#ifndef TUNNEL_H
#define TUNNEL_H

#include "v6gw.h"

/* Initialize tunnel subsystem */
int tunnel_init(void);

/* Create and bring up a tunnel */
int tunnel_up(tunnel_t *tunnel);

/* Bring down a tunnel */
int tunnel_down(tunnel_t *tunnel);

/* Check tunnel health */
int tunnel_check(tunnel_t *tunnel);

/* Get tunnel statistics */
int tunnel_get_stats(tunnel_t *tunnel);

/* Calculate tunnel health score (0-100) */
int tunnel_calculate_health(tunnel_t *tunnel);

/* Select best tunnel based on health scores */
tunnel_t* tunnel_select_best(tunnel_t *tunnels, int tunnel_count);

/* Perform automatic failover if primary tunnel is down */
int tunnel_auto_failover(tunnel_t *tunnels, int tunnel_count);

/* Cleanup tunnel subsystem */
void tunnel_cleanup(void);

#endif /* TUNNEL_H */
