/*
 * REST API server implementation
 * HTTP+JSON API with CNSA 2.0 authentication
 */

#include "api.h"
#include "log.h"
#include "health.h"
#include "session.h"
#include "crypto.h"
#include "hwauth.h"
#include "proxy.h"
#include "v6gw.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>

static int api_sockfd = -1;
static struct sockaddr_in api_addr;

/* Extract session ID from Authorization header */
static int extract_session_id(const char *request, uint8_t *session_id) {
    const char *auth_header = strstr(request, "Authorization: Bearer ");
    if (!auth_header) {
        return -1;
    }

    auth_header += 22;  /* Skip "Authorization: Bearer " */

    /* Session ID is hex-encoded */
    char hex_id[SESSION_ID_BYTES * 2 + 1];
    if (sscanf(auth_header, "%64s", hex_id) != 1) {
        return -1;
    }

    /* Convert hex to bytes */
    for (int i = 0; i < SESSION_ID_BYTES; i++) {
        if (sscanf(hex_id + (i * 2), "%2hhx", &session_id[i]) != 1) {
            return -1;
        }
    }

    return 0;
}

/* Check if request is authenticated */
static session_t* authenticate_request(const char *request) {
    if (!g_ctx.config.crypto_enabled) {
        return NULL;  /* Auth disabled, allow request */
    }

    uint8_t session_id[SESSION_ID_BYTES];
    if (extract_session_id(request, session_id) != 0) {
        return NULL;
    }

    session_t *session = NULL;
    if (session_validate(session_id, &session) != 0) {
        return NULL;
    }

    session_touch(session);
    return session;
}

/* Simple HTTP response builder */
static void send_http_response(int client_fd, int status_code, const char *status_text,
                               const char *content_type, const char *body) {
    char response[4096];
    int body_len = body ? strlen(body) : 0;

    int len = snprintf(response, sizeof(response),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "\r\n"
        "%s",
        status_code, status_text,
        content_type,
        body_len,
        body ? body : "");

    send(client_fd, response, len, 0);
}

static void send_json_response(int client_fd, int status_code, const char *status_text, const char *json) {
    send_http_response(client_fd, status_code, status_text, "application/json", json);
}

/* API endpoint: GET /health */
static void handle_health(int client_fd) {
    health_status_t status;
    health_check_all(&status);

    char json[1024];
    snprintf(json, sizeof(json),
        "{\n"
        "  \"status\": \"%s\",\n"
        "  \"v6_reachable\": %s,\n"
        "  \"v6_latency_ms\": %d,\n"
        "  \"active_tunnels\": %d,\n"
        "  \"last_check\": %ld\n"
        "}",
        status.v6_reachable ? "ok" : "degraded",
        status.v6_reachable ? "true" : "false",
        status.v6_latency_ms,
        status.active_tunnels,
        status.last_check);

    send_json_response(client_fd, 200, "OK", json);
}

/* API endpoint: GET /v6/address */
static void handle_v6_address(int client_fd) {
    char json[2048];
    int offset = 0;

    offset += snprintf(json + offset, sizeof(json) - offset, "{\n  \"addresses\": [\n");

    for (int i = 0; i < g_ctx.tunnel_count; i++) {
        tunnel_t *t = &g_ctx.tunnels[i];
        if (t->state != TUNNEL_STATE_UP) continue;

        char addr_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &t->v6_addr, addr_str, sizeof(addr_str));

        if (i > 0 && offset < sizeof(json)) {
            offset += snprintf(json + offset, sizeof(json) - offset, ",\n");
        }

        offset += snprintf(json + offset, sizeof(json) - offset,
            "    {\n"
            "      \"iface\": \"%s\",\n"
            "      \"address\": \"%s\",\n"
            "      \"prefix\": %d,\n"
            "      \"reachable\": %s,\n"
            "      \"latency_ms\": %d\n"
            "    }",
            t->config.iface,
            addr_str,
            t->config.prefix_len,
            t->reachable ? "true" : "false",
            t->latency_ms);
    }

    offset += snprintf(json + offset, sizeof(json) - offset, "\n  ]\n}");

    send_json_response(client_fd, 200, "OK", json);
}

/* API endpoint: GET /tunnels */
static void handle_tunnels(int client_fd) {
    char json[4096];
    int offset = 0;

    offset += snprintf(json + offset, sizeof(json) - offset, "{\n  \"tunnels\": [\n");

    for (int i = 0; i < g_ctx.tunnel_count; i++) {
        tunnel_t *t = &g_ctx.tunnels[i];

        if (i > 0) {
            offset += snprintf(json + offset, sizeof(json) - offset, ",\n");
        }

        const char *state_str = (t->state == TUNNEL_STATE_UP) ? "up" :
                               (t->state == TUNNEL_STATE_DOWN) ? "down" : "error";
        const char *type_str = (t->config.type == TUNNEL_TYPE_HE_6IN4) ? "he_6in4" :
                              (t->config.type == TUNNEL_TYPE_WIREGUARD) ? "wireguard" : "external";

        offset += snprintf(json + offset, sizeof(json) - offset,
            "    {\n"
            "      \"name\": \"%s\",\n"
            "      \"type\": \"%s\",\n"
            "      \"state\": \"%s\",\n"
            "      \"iface\": \"%s\",\n"
            "      \"v6_prefix\": \"%s/%d\",\n"
            "      \"rx_bytes\": %u,\n"
            "      \"tx_bytes\": %u,\n"
            "      \"last_check\": %ld\n"
            "    }",
            t->config.name,
            type_str,
            state_str,
            t->config.iface,
            t->config.v6_prefix,
            t->config.prefix_len,
            t->rx_bytes,
            t->tx_bytes,
            t->last_check);
    }

    offset += snprintf(json + offset, sizeof(json) - offset, "\n  ]\n}");

    send_json_response(client_fd, 200, "OK", json);
}

/* API endpoint: POST /auth/login */
static void handle_auth_login(int client_fd, const char *request_body) {
    if (!g_ctx.config.crypto_enabled || !g_ctx.crypto_initialized) {
        send_json_response(client_fd, 503, "Service Unavailable",
                          "{\"error\": \"Authentication not available\"}");
        return;
    }

    /* Parse username from request body (simple JSON parsing) */
    char username[256] = "root";  /* Default for now */
    const char *user_field = strstr(request_body, "\"username\":");
    if (user_field) {
        sscanf(user_field, "\"username\":\"%255[^\"]\"", username);
    }

    /* Perform hardware authentication */
    hwauth_result_t hw_result;
    if (hwauth_authenticate(username, &hw_result) != 0) {
        log_warn("Hardware authentication failed for user '%s'", username);
        send_json_response(client_fd, 401, "Unauthorized",
                          "{\"error\": \"Hardware authentication required\"}");
        return;
    }

    /* Generate ML-KEM-1024 shared secret */
    uint8_t ciphertext[MLKEM_1024_CIPHERTEXT_BYTES];
    uint8_t shared_secret[MLKEM_1024_SHARED_SECRET_BYTES];

    if (crypto_mlkem_encapsulate(g_ctx.kem_keys.public_key, ciphertext, shared_secret) != 0) {
        log_error("Failed to generate shared secret");
        send_json_response(client_fd, 500, "Internal Server Error",
                          "{\"error\": \"Cryptographic failure\"}");
        return;
    }

    /* Create session */
    session_t *session = NULL;
    if (session_create(username, shared_secret, hw_result.method_used, &session) != 0) {
        log_error("Failed to create session for user '%s'", username);
        send_json_response(client_fd, 500, "Internal Server Error",
                          "{\"error\": \"Session creation failed\"}");
        return;
    }

    /* Create authentication token */
    crypto_token_t token;
    if (crypto_create_token(&g_ctx.dsa_keys, &token) != 0) {
        log_error("Failed to create auth token");
        send_json_response(client_fd, 500, "Internal Server Error",
                          "{\"error\": \"Token creation failed\"}");
        return;
    }

    session->auth_token = token;

    /* Return session ID (hex-encoded) */
    char session_id_hex[SESSION_ID_BYTES * 2 + 1];
    for (int i = 0; i < SESSION_ID_BYTES; i++) {
        sprintf(session_id_hex + (i * 2), "%02x", session->session_id[i]);
    }
    session_id_hex[SESSION_ID_BYTES * 2] = '\0';

    char json[2048];
    snprintf(json, sizeof(json),
        "{\n"
        "  \"status\": \"authenticated\",\n"
        "  \"username\": \"%s\",\n"
        "  \"session_id\": \"%s\",\n"
        "  \"auth_method\": \"%s\",\n"
        "  \"expires\": %ld\n"
        "}",
        session->username,
        session_id_hex,
        (hw_result.method_used == HWAUTH_TYPE_FINGERPRINT) ? "fingerprint" : "yubikey",
        session->expires);

    log_info("User '%s' authenticated successfully via %s",
             username,
             (hw_result.method_used == HWAUTH_TYPE_FINGERPRINT) ? "fingerprint" : "yubikey");

    send_json_response(client_fd, 200, "OK", json);
}

/* API endpoint: POST /auth/logout */
static void handle_auth_logout(int client_fd, const char *request) {
    uint8_t session_id[SESSION_ID_BYTES];
    if (extract_session_id(request, session_id) != 0) {
        send_json_response(client_fd, 400, "Bad Request",
                          "{\"error\": \"Invalid session\"}");
        return;
    }

    if (session_destroy(session_id) == 0) {
        send_json_response(client_fd, 200, "OK",
                          "{\"status\": \"logged_out\"}");
    } else {
        send_json_response(client_fd, 404, "Not Found",
                          "{\"error\": \"Session not found\"}");
    }
}

/* API endpoint: GET /auth/status */
static void handle_auth_status(int client_fd, const char *request) {
    session_t *session = authenticate_request(request);

    if (!session) {
        send_json_response(client_fd, 401, "Unauthorized",
                          "{\"error\": \"Not authenticated\"}");
        return;
    }

    char json[1024];
    snprintf(json, sizeof(json),
        "{\n"
        "  \"authenticated\": true,\n"
        "  \"username\": \"%s\",\n"
        "  \"auth_method\": \"%s\",\n"
        "  \"created\": %ld,\n"
        "  \"expires\": %ld,\n"
        "  \"last_activity\": %ld,\n"
        "  \"request_count\": %u\n"
        "}",
        session->username,
        (session->auth_method == HWAUTH_TYPE_FINGERPRINT) ? "fingerprint" : "yubikey",
        session->created,
        session->expires,
        session->last_activity,
        session->request_count);

    send_json_response(client_fd, 200, "OK", json);
}

/* Route incoming HTTP request */
/* API endpoint: POST /ports/udp */
static void handle_add_udp_port(int client_fd, const char *request_body) {
    /* Parse JSON body: {"internal_port":7654, "external_port":7654, "v6_address":"2001:db8::1", "description":"I2P-UDP"} */
    int internal_port = 0, external_port = 0;
    char v6_address[INET6_ADDRSTRLEN] = {0};
    char description[128] = {0};

    if (sscanf(request_body,
               "{\"internal_port\":%d,\"external_port\":%d,\"v6_address\":\"%[^\"]\",\"description\":\"%[^\"]\"}",
               &internal_port, &external_port, v6_address, description) < 2) {
        send_json_response(client_fd, 400, "Bad Request",
                          "{\"error\": \"Invalid JSON body\"}");
        return;
    }

    if (g_ctx.config.mode != MODE_PROXY) {
        send_json_response(client_fd, 400, "Bad Request",
                          "{\"error\": \"Proxy mode not enabled\"}");
        return;
    }

    struct in6_addr remote_addr;
    if (inet_pton(AF_INET6, v6_address, &remote_addr) != 1) {
        send_json_response(client_fd, 400, "Bad Request",
                          "{\"error\": \"Invalid IPv6 address\"}");
        return;
    }

    if (proxy_add_udp_mapping(internal_port, &remote_addr, external_port, description) != 0) {
        send_json_response(client_fd, 500, "Internal Server Error",
                          "{\"error\": \"Failed to create UDP mapping\"}");
        return;
    }

    char response[512];
    snprintf(response, sizeof(response),
             "{\"status\": \"ok\", \"internal_port\": %d, \"external_port\": %d, \"v6_address\": \"%s\"}",
             internal_port, external_port, v6_address);
    send_json_response(client_fd, 200, "OK", response);
}

/* API endpoint: POST /ports/tcp */
static void handle_add_tcp_port(int client_fd, const char *request_body) {
    int internal_port = 0, external_port = 0;
    char v6_address[INET6_ADDRSTRLEN] = {0};
    char description[128] = {0};

    if (sscanf(request_body,
               "{\"internal_port\":%d,\"external_port\":%d,\"v6_address\":\"%[^\"]\",\"description\":\"%[^\"]\"}",
               &internal_port, &external_port, v6_address, description) < 2) {
        send_json_response(client_fd, 400, "Bad Request",
                          "{\"error\": \"Invalid JSON body\"}");
        return;
    }

    if (g_ctx.config.mode != MODE_PROXY) {
        send_json_response(client_fd, 400, "Bad Request",
                          "{\"error\": \"Proxy mode not enabled\"}");
        return;
    }

    struct in6_addr remote_addr;
    if (inet_pton(AF_INET6, v6_address, &remote_addr) != 1) {
        send_json_response(client_fd, 400, "Bad Request",
                          "{\"error\": \"Invalid IPv6 address\"}");
        return;
    }

    if (proxy_add_tcp_mapping(internal_port, &remote_addr, external_port, description) != 0) {
        send_json_response(client_fd, 500, "Internal Server Error",
                          "{\"error\": \"Failed to create TCP mapping\"}");
        return;
    }

    char response[512];
    snprintf(response, sizeof(response),
             "{\"status\": \"ok\", \"internal_port\": %d, \"external_port\": %d, \"v6_address\": \"%s\"}",
             internal_port, external_port, v6_address);
    send_json_response(client_fd, 200, "OK", response);
}

/* API endpoint: GET /probe/udp?port=XXXX */
static void handle_probe_udp(int client_fd, const char *path) {
    /* Extract port from query string */
    int port = 0;
    const char *query = strchr(path, '?');
    if (query && sscanf(query, "?port=%d", &port) == 1) {
        /* Simple UDP probe - in production would use external probe service */
        char response[256];
        snprintf(response, sizeof(response),
                 "{\"status\": \"probe_initiated\", \"port\": %d, "
                 "\"note\": \"External UDP probe not implemented - use external tools to verify reachability\"}",
                 port);
        send_json_response(client_fd, 200, "OK", response);
    } else {
        send_json_response(client_fd, 400, "Bad Request",
                          "{\"error\": \"Missing or invalid port parameter\"}");
    }
}

static void handle_request(int client_fd, const char *request) {
    char method[16], path[256];

    if (sscanf(request, "%15s %255s", method, path) != 2) {
        send_json_response(client_fd, 400, "Bad Request", "{\"error\": \"Invalid request\"}");
        return;
    }

    log_debug("API: %s %s", method, path);

    /* Handle POST requests for auth and proxy endpoints */
    if (strcmp(method, "POST") == 0) {
        /* Extract request body */
        const char *body_start = strstr(request, "\r\n\r\n");
        const char *body = body_start ? body_start + 4 : "";

        if (strcmp(path, "/auth/login") == 0) {
            handle_auth_login(client_fd, body);
            return;
        } else if (strcmp(path, "/auth/logout") == 0) {
            handle_auth_logout(client_fd, request);
            return;
        } else if (strcmp(path, "/ports/udp") == 0) {
            handle_add_udp_port(client_fd, body);
            return;
        } else if (strcmp(path, "/ports/tcp") == 0) {
            handle_add_tcp_port(client_fd, body);
            return;
        }
        send_json_response(client_fd, 404, "Not Found", "{\"error\": \"Endpoint not found\"}");
        return;
    }

    /* Handle GET requests */
    if (strcmp(method, "GET") != 0) {
        send_json_response(client_fd, 405, "Method Not Allowed",
                          "{\"error\": \"Method not supported\"}");
        return;
    }

    /* Public endpoints (no auth required) */
    if (strcmp(path, "/") == 0) {
        const char *info = "{"
            "\"service\": \"v6-gatewayd\","
            "\"version\": \"" VERSION "\","
            "\"crypto_enabled\": " "true" ","
            "\"endpoints\": [\"/health\", \"/v6/address\", \"/tunnels\", \"/auth/login\", \"/auth/logout\", \"/auth/status\", \"/ports/udp\", \"/ports/tcp\", \"/probe/udp\"  ]"
            "}";
        send_json_response(client_fd, 200, "OK", info);
        return;
    } else if (strcmp(path, "/health") == 0) {
        handle_health(client_fd);
        return;
    } else if (strncmp(path, "/probe/udp", 10) == 0) {
        handle_probe_udp(client_fd, path);
        return;
    }

    /* Auth status endpoint */
    if (strcmp(path, "/auth/status") == 0) {
        handle_auth_status(client_fd, request);
        return;
    }

    /* Protected endpoints - require authentication if crypto enabled */
    if (g_ctx.config.crypto_enabled) {
        session_t *session = authenticate_request(request);
        if (!session) {
            send_json_response(client_fd, 401, "Unauthorized",
                              "{\"error\": \"Authentication required\"}");
            return;
        }
    }

    /* Handle protected endpoints */
    if (strcmp(path, "/v6/address") == 0) {
        handle_v6_address(client_fd);
    } else if (strcmp(path, "/tunnels") == 0) {
        handle_tunnels(client_fd);
    } else {
        send_json_response(client_fd, 404, "Not Found", "{\"error\": \"Endpoint not found\"}");
    }
}

int api_init(const api_config_t *config) {
    log_info("Initializing API server on %s:%d", config->bind_addr, config->port);

    api_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (api_sockfd < 0) {
        log_error("Failed to create API socket");
        return -1;
    }

    /* Set socket options */
    int opt = 1;
    setsockopt(api_sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* Set non-blocking */
    int flags = fcntl(api_sockfd, F_GETFL, 0);
    fcntl(api_sockfd, F_SETFL, flags | O_NONBLOCK);

    /* Bind */
    memset(&api_addr, 0, sizeof(api_addr));
    api_addr.sin_family = AF_INET;
    api_addr.sin_port = htons(config->port);
    inet_pton(AF_INET, config->bind_addr, &api_addr.sin_addr);

    if (bind(api_sockfd, (struct sockaddr*)&api_addr, sizeof(api_addr)) < 0) {
        log_error("Failed to bind API socket: %s", strerror(errno));
        close(api_sockfd);
        return -1;
    }

    /* Listen */
    if (listen(api_sockfd, config->backlog) < 0) {
        log_error("Failed to listen on API socket");
        close(api_sockfd);
        return -1;
    }

    log_info("API server initialized successfully");
    return 0;
}

int api_start(void) {
    log_info("API server started");
    return 0;
}

int api_process(void) {
    if (api_sockfd < 0) {
        return -1;
    }

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    int client_fd = accept(api_sockfd, (struct sockaddr*)&client_addr, &client_len);
    if (client_fd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            log_error("accept() failed: %s", strerror(errno));
        }
        return 0;
    }

    /* Read request */
    char request[2048];
    ssize_t n = recv(client_fd, request, sizeof(request) - 1, 0);
    if (n > 0) {
        request[n] = '\0';
        handle_request(client_fd, request);
    }

    close(client_fd);
    return 0;
}

void api_stop(void) {
    log_info("Stopping API server");
    if (api_sockfd >= 0) {
        close(api_sockfd);
        api_sockfd = -1;
    }
}

void api_cleanup(void) {
    api_stop();
}
