/*
 * Session Management Implementation
 */

#include "session.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static session_manager_t g_session_manager = {0};
static bool g_session_initialized = false;

int session_init(void) {
    if (g_session_initialized) {
        return 0;
    }

    memset(&g_session_manager, 0, sizeof(g_session_manager));
    g_session_manager.cleanup_interval = 300;  /* 5 minutes */
    g_session_manager.last_cleanup = time(NULL);

    log_info("Session manager initialized");
    g_session_initialized = true;
    return 0;
}

int session_create(const char *username,
                   const uint8_t *shared_secret,
                   hwauth_type_t auth_method,
                   session_t **out_session) {
    if (!g_session_initialized || !username || !shared_secret || !out_session) {
        return -1;
    }

    /* Check for available slot */
    if (g_session_manager.session_count >= MAX_SESSIONS) {
        log_warn("Maximum sessions reached, cleaning up expired");
        session_cleanup_expired();
        if (g_session_manager.session_count >= MAX_SESSIONS) {
            log_error("No available session slots");
            return -1;
        }
    }

    /* Find first inactive slot */
    session_t *session = NULL;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!g_session_manager.sessions[i].active) {
            session = &g_session_manager.sessions[i];
            break;
        }
    }

    if (!session) {
        return -1;
    }

    /* Initialize session */
    memset(session, 0, sizeof(*session));

    /* Generate session ID from shared secret + timestamp */
    uint8_t session_data[MLKEM_1024_SHARED_SECRET_BYTES + sizeof(time_t)];
    time_t now = time(NULL);
    memcpy(session_data, shared_secret, MLKEM_1024_SHARED_SECRET_BYTES);
    memcpy(session_data + MLKEM_1024_SHARED_SECRET_BYTES, &now, sizeof(time_t));

    uint8_t hash[SHA384_DIGEST_BYTES];
    crypto_sha384(session_data, sizeof(session_data), hash);
    memcpy(session->session_id, hash, SESSION_ID_BYTES);

    /* Create crypto session */
    if (crypto_create_session(shared_secret, &session->crypto_session) != 0) {
        log_error("Failed to create crypto session");
        return -1;
    }

    /* Set session properties */
    snprintf(session->username, sizeof(session->username), "%s", username);
    session->auth_method = auth_method;
    session->created = now;
    session->last_activity = now;
    session->expires = now + 3600;  /* 1 hour */
    session->active = true;
    session->request_count = 0;

    g_session_manager.session_count++;
    *out_session = session;

    log_info("Created session for user '%s' (method: %d)", username, auth_method);
    return 0;
}

int session_validate(const uint8_t *session_id, session_t **out_session) {
    if (!g_session_initialized || !session_id || !out_session) {
        return -1;
    }

    /* Find session */
    for (int i = 0; i < MAX_SESSIONS; i++) {
        session_t *s = &g_session_manager.sessions[i];
        if (s->active && memcmp(s->session_id, session_id, SESSION_ID_BYTES) == 0) {
            /* Check if expired */
            time_t now = time(NULL);
            if (now > s->expires) {
                log_debug("Session expired for user '%s'", s->username);
                s->active = false;
                g_session_manager.session_count--;
                return -1;
            }

            /* Validate crypto session */
            if (crypto_validate_session(&s->crypto_session) != 0) {
                log_warn("Crypto session invalid for user '%s'", s->username);
                s->active = false;
                g_session_manager.session_count--;
                return -1;
            }

            *out_session = s;
            return 0;
        }
    }

    log_debug("Session not found");
    return -1;
}

int session_touch(session_t *session) {
    if (!session || !session->active) {
        return -1;
    }

    time_t now = time(NULL);
    session->last_activity = now;
    session->request_count++;

    /* Extend expiration if close to expiring */
    if (session->expires - now < 600) {  /* Less than 10 minutes */
        session->expires = now + 3600;  /* Extend by 1 hour */
        log_debug("Extended session for user '%s'", session->username);
    }

    return 0;
}

int session_destroy(const uint8_t *session_id) {
    if (!g_session_initialized || !session_id) {
        return -1;
    }

    for (int i = 0; i < MAX_SESSIONS; i++) {
        session_t *s = &g_session_manager.sessions[i];
        if (s->active && memcmp(s->session_id, session_id, SESSION_ID_BYTES) == 0) {
            log_info("Destroying session for user '%s'", s->username);

            /* Wipe session data */
            crypto_destroy_session(&s->crypto_session);
            memset(s, 0, sizeof(*s));
            s->active = false;

            g_session_manager.session_count--;
            return 0;
        }
    }

    return -1;
}

int session_cleanup_expired(void) {
    if (!g_session_initialized) {
        return -1;
    }

    time_t now = time(NULL);
    int cleaned = 0;

    for (int i = 0; i < MAX_SESSIONS; i++) {
        session_t *s = &g_session_manager.sessions[i];
        if (s->active && now > s->expires) {
            log_debug("Cleaning up expired session for user '%s'", s->username);
            crypto_destroy_session(&s->crypto_session);
            memset(s, 0, sizeof(*s));
            s->active = false;
            g_session_manager.session_count--;
            cleaned++;
        }
    }

    if (cleaned > 0) {
        log_info("Cleaned up %d expired sessions", cleaned);
    }

    g_session_manager.last_cleanup = now;
    return cleaned;
}

int session_get_stats(int *active_count, int *total_count) {
    if (!g_session_initialized) {
        return -1;
    }

    int active = 0;
    int total = 0;

    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (g_session_manager.sessions[i].active) {
            active++;
        }
        total++;
    }

    if (active_count) *active_count = active;
    if (total_count) *total_count = MAX_SESSIONS;

    return 0;
}

void session_cleanup(void) {
    if (!g_session_initialized) {
        return;
    }

    log_info("Cleaning up session manager");

    /* Destroy all active sessions */
    for (int i = 0; i < MAX_SESSIONS; i++) {
        session_t *s = &g_session_manager.sessions[i];
        if (s->active) {
            crypto_destroy_session(&s->crypto_session);
            memset(s, 0, sizeof(*s));
        }
    }

    memset(&g_session_manager, 0, sizeof(g_session_manager));
    g_session_initialized = false;
}
