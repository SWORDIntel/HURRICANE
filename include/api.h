/*
 * REST API server (HTTP+JSON)
 */

#ifndef API_H
#define API_H

#include "v6gw.h"

/* API server configuration */
typedef struct {
    const char *bind_addr;
    int port;
    int backlog;
} api_config_t;

/* Initialize API server */
int api_init(const api_config_t *config);

/* Start API server (non-blocking) */
int api_start(void);

/* Stop API server */
void api_stop(void);

/* Process API requests (call in main loop) */
int api_process(void);

/* Cleanup API server */
void api_cleanup(void);

#endif /* API_H */
