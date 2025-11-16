/*
 * Hardware Authentication Implementation
 * Fingerprint reader and YubiKey support via PAM
 */

#include "hwauth.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#ifdef HAVE_LIBPAM
#include <security/pam_appl.h>
#else
#warning "libpam not available - hardware auth will be disabled"
#endif

#ifdef HAVE_LIBFPRINT
#include <libfprint/fprint.h>
#else
#warning "libfprint not available - fingerprint auth will be disabled"
#endif

#ifdef HAVE_LIBYKPERS
#include <ykpers.h>
#else
#warning "libykpers not available - YubiKey auth will be disabled"
#endif

static hwauth_config_t g_hwauth_config = {0};
static bool g_hwauth_initialized = false;

#ifdef HAVE_LIBPAM
/* PAM conversation function */
static int pam_conv_func(int num_msg, const struct pam_message **msg,
                        struct pam_response **resp, void *appdata_ptr) {
    (void)msg;
    (void)appdata_ptr;

    if (num_msg <= 0) {
        return PAM_CONV_ERR;
    }

    /* Allocate response array */
    *resp = calloc(num_msg, sizeof(struct pam_response));
    if (!*resp) {
        return PAM_BUF_ERR;
    }

    /* For hardware auth, we don't need to provide password */
    return PAM_SUCCESS;
}

static struct pam_conv pam_conversation = {
    .conv = pam_conv_func,
    .appdata_ptr = NULL
};
#endif

int hwauth_init(const hwauth_config_t *config) {
    if (g_hwauth_initialized) {
        return 0;
    }

    if (!config) {
        return -1;
    }

    memcpy(&g_hwauth_config, config, sizeof(hwauth_config_t));

    log_info("Initializing hardware authentication");

    /* Check fingerprint availability */
    if (g_hwauth_config.required_methods & HWAUTH_TYPE_FINGERPRINT) {
        if (hwauth_fingerprint_available()) {
            log_info("Fingerprint reader detected and available");
        } else {
            log_warn("Fingerprint reader not available");
            if (!g_hwauth_config.allow_fallback) {
                return -1;
            }
        }
    }

    /* Check YubiKey availability */
    if (g_hwauth_config.required_methods & HWAUTH_TYPE_YUBIKEY) {
        if (hwauth_yubikey_available()) {
            log_info("YubiKey support enabled");
        } else {
            log_warn("YubiKey not detected");
            if (!g_hwauth_config.allow_fallback) {
                return -1;
            }
        }
    }

    g_hwauth_initialized = true;
    return 0;
}

bool hwauth_fingerprint_available(void) {
#ifdef HAVE_LIBFPRINT
    /* Check if libfprint can detect a fingerprint device */
    fp_init();
    fp_dev **devices = fp_discover_devs();
    if (devices && devices[0]) {
        fp_dscv_devs_free(devices);
        fp_exit();
        return true;
    }
    fp_exit();
    return false;
#else
    return false;
#endif
}

bool hwauth_yubikey_available(void) {
#ifdef HAVE_LIBYKPERS
    /* Check if a YubiKey is present */
    if (yk_init()) {
        YK_KEY *yk = yk_open_first_key();
        if (yk) {
            yk_close_key(yk);
            yk_release();
            return true;
        }
        yk_release();
    }
    return false;
#else
    return false;
#endif
}

int hwauth_authenticate(const char *username, hwauth_result_t *result) {
    if (!g_hwauth_initialized || !username || !result) {
        return -1;
    }

    memset(result, 0, sizeof(*result));
    snprintf(result->username, sizeof(result->username), "%s", username);
    result->timestamp = time(NULL);
    result->authenticated = false;

#ifdef HAVE_LIBPAM
    pam_handle_t *pamh = NULL;
    int pam_ret;

    /* Try fingerprint authentication first */
    if (g_hwauth_config.required_methods & HWAUTH_TYPE_FINGERPRINT) {
        log_debug("Attempting fingerprint authentication for %s", username);

        pam_ret = pam_start("v6-gatewayd-fingerprint", username, &pam_conversation, &pamh);
        if (pam_ret == PAM_SUCCESS) {
            pam_ret = pam_authenticate(pamh, 0);
            if (pam_ret == PAM_SUCCESS) {
                log_info("Fingerprint authentication successful for %s", username);
                result->authenticated = true;
                result->method_used = HWAUTH_TYPE_FINGERPRINT;
                pam_end(pamh, PAM_SUCCESS);
                return 0;
            }
            pam_end(pamh, pam_ret);
        }
    }

    /* Try YubiKey authentication */
    if (g_hwauth_config.required_methods & HWAUTH_TYPE_YUBIKEY) {
        log_debug("Attempting YubiKey authentication for %s", username);

        pam_ret = pam_start("v6-gatewayd-yubikey", username, &pam_conversation, &pamh);
        if (pam_ret == PAM_SUCCESS) {
            pam_ret = pam_authenticate(pamh, 0);
            if (pam_ret == PAM_SUCCESS) {
                log_info("YubiKey authentication successful for %s", username);
                result->authenticated = true;
                result->method_used = HWAUTH_TYPE_YUBIKEY;
                pam_end(pamh, PAM_SUCCESS);
                return 0;
            }
            pam_end(pamh, pam_ret);
        }
    }

    log_warn("Hardware authentication failed for %s", username);
    return -1;
#else
    log_error("PAM support not available - hardware authentication disabled");
    return -1;
#endif
}

void hwauth_cleanup(void) {
    if (!g_hwauth_initialized) {
        return;
    }

    log_info("Cleaning up hardware authentication");
    g_hwauth_initialized = false;
    memset(&g_hwauth_config, 0, sizeof(g_hwauth_config));
}
