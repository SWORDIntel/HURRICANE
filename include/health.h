/*
 * Health check system
 */

#ifndef HEALTH_H
#define HEALTH_H

#include "v6gw.h"

/* Health status */
typedef struct {
    bool v6_reachable;
    int v6_latency_ms;
    time_t last_check;
    int active_tunnels;
} health_status_t;

/* Initialize health check system */
int health_init(void);

/* Perform IPv6 ping to test host */
int health_ping_v6(const char *target, int *latency_ms);

/* Check overall system health */
int health_check_all(health_status_t *status);

/* Cleanup health check system */
void health_cleanup(void);

#endif /* HEALTH_H */
