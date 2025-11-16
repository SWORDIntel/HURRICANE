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

/* Cleanup tunnel subsystem */
void tunnel_cleanup(void);

#endif /* TUNNEL_H */
