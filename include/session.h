/*
 * Session Management
 * Handles authenticated sessions with CNSA 2.0 crypto
 */

#ifndef SESSION_H
#define SESSION_H

#include "crypto.h"
#include "hwauth.h"
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#define MAX_SESSIONS 64
#define SESSION_ID_BYTES 32

/* Session structure */
typedef struct {
    uint8_t session_id[SESSION_ID_BYTES];
    char username[256];
    crypto_session_t crypto_session;
    crypto_token_t auth_token;
    hwauth_type_t auth_method;
    time_t created;
    time_t last_activity;
    time_t expires;
    bool active;
    uint32_t request_count;
} session_t;

/* Session manager */
typedef struct {
    session_t sessions[MAX_SESSIONS];
    int session_count;
    time_t cleanup_interval;
    time_t last_cleanup;
} session_manager_t;

/* Initialize session manager */
int session_init(void);

/* Create new session after authentication */
int session_create(const char *username,
                   const uint8_t *shared_secret,
                   hwauth_type_t auth_method,
                   session_t **out_session);

/* Validate session by ID */
int session_validate(const uint8_t *session_id, session_t **out_session);

/* Update session activity */
int session_touch(session_t *session);

/* Destroy session (logout) */
int session_destroy(const uint8_t *session_id);

/* Cleanup expired sessions */
int session_cleanup_expired(void);

/* Get session statistics */
int session_get_stats(int *active_count, int *total_count);

/* Cleanup session manager */
void session_cleanup(void);

#endif /* SESSION_H */
