/*
 * Hardware Authentication Module
 * Fingerprint reader and YubiKey support via PAM
 */

#ifndef HWAUTH_H
#define HWAUTH_H

#include <stdbool.h>
#include <time.h>

/* Hardware authentication types */
typedef enum {
    HWAUTH_TYPE_NONE        = 0,
    HWAUTH_TYPE_FINGERPRINT = 1,
    HWAUTH_TYPE_YUBIKEY     = 2,
    HWAUTH_TYPE_BOTH        = 3  /* Fingerprint OR YubiKey */
} hwauth_type_t;

/* Authentication result */
typedef struct {
    bool authenticated;
    hwauth_type_t method_used;
    char username[256];
    time_t timestamp;
} hwauth_result_t;

/* Configuration */
typedef struct {
    hwauth_type_t required_methods;
    bool allow_fallback;
    int timeout_seconds;
    char pam_service[64];
} hwauth_config_t;

/* Initialize hardware authentication */
int hwauth_init(const hwauth_config_t *config);

/* Authenticate user with hardware */
int hwauth_authenticate(const char *username, hwauth_result_t *result);

/* Check if fingerprint reader is available */
bool hwauth_fingerprint_available(void);

/* Check if YubiKey is available */
bool hwauth_yubikey_available(void);

/* Cleanup hardware authentication */
void hwauth_cleanup(void);

#endif /* HWAUTH_H */
