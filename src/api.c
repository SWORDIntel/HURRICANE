/*
 * REST API server implementation
 * Simple HTTP+JSON API for tunnel management and status
 */

#include "api.h"
#include "log.h"
#include "health.h"
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

/* Route incoming HTTP request */
static void handle_request(int client_fd, const char *request) {
    char method[16], path[256];

    if (sscanf(request, "%15s %255s", method, path) != 2) {
        send_json_response(client_fd, 400, "Bad Request", "{\"error\": \"Invalid request\"}");
        return;
    }

    log_debug("API: %s %s", method, path);

    if (strcmp(method, "GET") != 0) {
        send_json_response(client_fd, 405, "Method Not Allowed",
                          "{\"error\": \"Only GET method is supported\"}");
        return;
    }

    if (strcmp(path, "/health") == 0) {
        handle_health(client_fd);
    } else if (strcmp(path, "/v6/address") == 0) {
        handle_v6_address(client_fd);
    } else if (strcmp(path, "/tunnels") == 0) {
        handle_tunnels(client_fd);
    } else if (strcmp(path, "/") == 0) {
        const char *info = "{"
            "\"service\": \"v6-gatewayd\","
            "\"version\": \"" VERSION "\","
            "\"endpoints\": [\"/health\", \"/v6/address\", \"/tunnels\"]"
            "}";
        send_json_response(client_fd, 200, "OK", info);
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
