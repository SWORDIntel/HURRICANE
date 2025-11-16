/*
 * Configuration file parser
 * Simple INI-style format for easy parsing without external libraries
 */

#include "config.h"
#include "log.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int parse_core_section(config_t *config, const char *key, const char *value) {
    if (strcmp(key, "log_level") == 0) {
        snprintf(config->log_level, sizeof(config->log_level), "%s", value);
    } else if (strcmp(key, "state_dir") == 0) {
        snprintf(config->state_dir, sizeof(config->state_dir), "%s", value);
    } else if (strcmp(key, "api_port") == 0) {
        config->api_port = atoi(value);
    } else if (strcmp(key, "api_bind") == 0) {
        snprintf(config->api_bind, sizeof(config->api_bind), "%s", value);
    }
    return 0;
}

static int parse_tunnel_section(tunnel_config_t *tunnel, const char *key, const char *value) {
    if (strcmp(key, "type") == 0) {
        if (strcmp(value, "he_6in4") == 0) {
            tunnel->type = TUNNEL_TYPE_HE_6IN4;
        } else if (strcmp(value, "wireguard") == 0) {
            tunnel->type = TUNNEL_TYPE_WIREGUARD;
        } else if (strcmp(value, "external") == 0) {
            tunnel->type = TUNNEL_TYPE_EXTERNAL;
        }
    } else if (strcmp(key, "iface") == 0) {
        snprintf(tunnel->iface, sizeof(tunnel->iface), "%s", value);
    } else if (strcmp(key, "endpoint_ipv4") == 0) {
        snprintf(tunnel->endpoint_ipv4, sizeof(tunnel->endpoint_ipv4), "%s", value);
    } else if (strcmp(key, "local_ipv4") == 0) {
        snprintf(tunnel->local_ipv4, sizeof(tunnel->local_ipv4), "%s", value);
    } else if (strcmp(key, "v6_prefix") == 0) {
        snprintf(tunnel->v6_prefix, sizeof(tunnel->v6_prefix), "%s", value);
    } else if (strcmp(key, "prefix_len") == 0) {
        tunnel->prefix_len = atoi(value);
    } else if (strcmp(key, "enabled") == 0) {
        tunnel->enabled = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
    }
    return 0;
}

int config_parse(const char *filename, config_t *config) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        log_error("Failed to open config file: %s", filename);
        return -1;
    }

    /* Set defaults */
    snprintf(config->log_level, sizeof(config->log_level), "info");
    snprintf(config->state_dir, sizeof(config->state_dir), "/var/lib/v6-gatewayd");
    config->api_port = 8642;
    snprintf(config->api_bind, sizeof(config->api_bind), "127.0.0.1");
    config->mode = MODE_KERNEL;
    config->tunnel_count = 0;
    config->crypto_enabled = false;
    snprintf(config->crypto_keyfile, sizeof(config->crypto_keyfile), "/var/lib/v6-gatewayd/keys.bin");

    char line[MAX_LINE];
    char section[64] = "";
    int current_tunnel = -1;

    while (fgets(line, sizeof(line), f)) {
        char *trimmed = trim(line);

        /* Skip empty lines and comments */
        if (trimmed[0] == '\0' || trimmed[0] == '#' || trimmed[0] == ';') {
            continue;
        }

        /* Section header */
        if (trimmed[0] == '[') {
            char *end = strchr(trimmed, ']');
            if (end) {
                *end = '\0';
                snprintf(section, sizeof(section), "%s", trimmed + 1);

                /* Check if this is a tunnel section */
                if (strncmp(section, "tunnel.", 7) == 0) {
                    if (config->tunnel_count < MAX_TUNNELS) {
                        current_tunnel = config->tunnel_count;
                        tunnel_config_t *t = &config->tunnels[current_tunnel];
                        memset(t, 0, sizeof(*t));
                        snprintf(t->name, sizeof(t->name), "%s", section + 7);
                        t->enabled = true;
                        config->tunnel_count++;
                    }
                } else {
                    current_tunnel = -1;
                }
            }
            continue;
        }

        /* Key-value pair */
        char *eq = strchr(trimmed, '=');
        if (eq) {
            *eq = '\0';
            char *key = trim(trimmed);
            char *value = trim(eq + 1);

            /* Remove quotes from value */
            if (value[0] == '"') {
                value++;
                char *end_quote = strchr(value, '"');
                if (end_quote) *end_quote = '\0';
            }

            if (strcmp(section, "core") == 0) {
                parse_core_section(config, key, value);
            } else if (strcmp(section, "crypto") == 0) {
                if (strcmp(key, "crypto_enabled") == 0) {
                    config->crypto_enabled = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
                } else if (strcmp(key, "crypto_keyfile") == 0) {
                    snprintf(config->crypto_keyfile, sizeof(config->crypto_keyfile), "%s", value);
                }
            } else if (strncmp(section, "tunnel.", 7) == 0 && current_tunnel >= 0) {
                parse_tunnel_section(&config->tunnels[current_tunnel], key, value);
            } else if (strcmp(section, "exposure") == 0) {
                if (strcmp(key, "mode") == 0) {
                    if (strcmp(value, "kernel") == 0) {
                        config->mode = MODE_KERNEL;
                    } else if (strcmp(value, "proxy") == 0) {
                        config->mode = MODE_PROXY;
                    } else if (strcmp(value, "socks5") == 0) {
                        config->mode = MODE_SOCKS5;
                    }
                }
            }
        }
    }

    fclose(f);
    log_info("Loaded configuration from %s", filename);
    return 0;
}

int config_validate(const config_t *config) {
    if (config->tunnel_count == 0) {
        log_error("No tunnels configured");
        return -1;
    }

    for (int i = 0; i < config->tunnel_count; i++) {
        const tunnel_config_t *t = &config->tunnels[i];
        if (t->enabled) {
            if (t->type == TUNNEL_TYPE_HE_6IN4) {
                if (strlen(t->endpoint_ipv4) == 0 || strlen(t->v6_prefix) == 0) {
                    log_error("Tunnel %s: missing required configuration", t->name);
                    return -1;
                }
            }
        }
    }

    return 0;
}

void config_print(const config_t *config) {
    log_debug("Configuration:");
    log_debug("  log_level: %s", config->log_level);
    log_debug("  state_dir: %s", config->state_dir);
    log_debug("  api_port: %d", config->api_port);
    log_debug("  api_bind: %s", config->api_bind);
    log_debug("  tunnel_count: %d", config->tunnel_count);

    for (int i = 0; i < config->tunnel_count; i++) {
        const tunnel_config_t *t = &config->tunnels[i];
        log_debug("  Tunnel %s:", t->name);
        log_debug("    enabled: %d", t->enabled);
        log_debug("    iface: %s", t->iface);
        log_debug("    v6_prefix: %s/%d", t->v6_prefix, t->prefix_len);
    }
}
