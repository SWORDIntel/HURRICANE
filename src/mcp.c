/*
 * MCP (Model Context Protocol) server implementation
 * Local-only interface via Unix socket for AI access to IPv6 gateway
 */

#include "mcp.h"
#include "log.h"
#include "health.h"
#include "v6gw.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <errno.h>

static int mcp_sockfd = -1;
static char mcp_socket_path[256] = "/var/run/v6-gatewayd-mcp.sock";

/* MCP JSON-RPC 2.0 response builder */
static void send_mcp_response(int client_fd, const char *id, const char *result) {
    char response[4096];
    snprintf(response, sizeof(response),
        "{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":%s}\n",
        id ? id : "null", result);
    send(client_fd, response, strlen(response), 0);
}

static void send_mcp_error(int client_fd, const char *id, int code, const char *message) {
    char response[1024];
    snprintf(response, sizeof(response),
        "{\"jsonrpc\":\"2.0\",\"id\":%s,\"error\":{\"code\":%d,\"message\":\"%s\"}}\n",
        id ? id : "null", code, message);
    send(client_fd, response, strlen(response), 0);
}

/* MCP tools/list - List available tools */
static void handle_tools_list(int client_fd, const char *id) {
    const char *tools =
        "{"
        "\"tools\":["
        "{"
        "\"name\":\"get_tunnel_status\","
        "\"description\":\"Get status of all IPv6 tunnels\","
        "\"inputSchema\":{\"type\":\"object\",\"properties\":{}}"
        "},"
        "{"
        "\"name\":\"get_ipv6_address\","
        "\"description\":\"Get available IPv6 addresses and their reachability\","
        "\"inputSchema\":{\"type\":\"object\",\"properties\":{}}"
        "},"
        "{"
        "\"name\":\"check_health\","
        "\"description\":\"Check overall IPv6 gateway health and connectivity\","
        "\"inputSchema\":{\"type\":\"object\",\"properties\":{}}"
        "}"
        "]"
        "}";

    send_mcp_response(client_fd, id, tools);
}

/* MCP tools/call - Execute a tool */
static void handle_tools_call(int client_fd, const char *id, const char *tool_name) {
    char result[4096];

    if (strcmp(tool_name, "get_tunnel_status") == 0) {
        int offset = snprintf(result, sizeof(result), "{\"content\":[{\"type\":\"text\",\"text\":\"");
        offset += snprintf(result + offset, sizeof(result) - offset, "Tunnel Status:\\n");

        for (int i = 0; i < g_ctx.tunnel_count; i++) {
            tunnel_t *t = &g_ctx.tunnels[i];
            const char *state = (t->state == TUNNEL_STATE_UP) ? "UP" :
                               (t->state == TUNNEL_STATE_DOWN) ? "DOWN" : "ERROR";

            offset += snprintf(result + offset, sizeof(result) - offset,
                "- %s (%s): %s [RX: %u bytes, TX: %u bytes]\\n",
                t->config.name, t->config.iface, state, t->rx_bytes, t->tx_bytes);
        }

        snprintf(result + offset, sizeof(result) - offset, "\"}]}");

    } else if (strcmp(tool_name, "get_ipv6_address") == 0) {
        int offset = snprintf(result, sizeof(result), "{\"content\":[{\"type\":\"text\",\"text\":\"");
        offset += snprintf(result + offset, sizeof(result) - offset, "IPv6 Addresses:\\n");

        for (int i = 0; i < g_ctx.tunnel_count; i++) {
            tunnel_t *t = &g_ctx.tunnels[i];
            if (t->state != TUNNEL_STATE_UP) continue;

            char addr_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &t->v6_addr, addr_str, sizeof(addr_str));

            offset += snprintf(result + offset, sizeof(result) - offset,
                "- %s/%d on %s (reachable: %s)\\n",
                addr_str, t->config.prefix_len, t->config.iface,
                t->reachable ? "yes" : "no");
        }

        snprintf(result + offset, sizeof(result) - offset, "\"}]}");

    } else if (strcmp(tool_name, "check_health") == 0) {
        health_status_t status;
        health_check_all(&status);

        snprintf(result, sizeof(result),
            "{\"content\":[{\"type\":\"text\",\"text\":"
            "\"Health Status:\\n"
            "- IPv6 Reachable: %s\\n"
            "- Latency: %d ms\\n"
            "- Active Tunnels: %d\\n"
            "- Last Check: %ld\"}]}",
            status.v6_reachable ? "Yes" : "No",
            status.v6_latency_ms,
            status.active_tunnels,
            status.last_check);

    } else {
        send_mcp_error(client_fd, id, -32601, "Tool not found");
        return;
    }

    send_mcp_response(client_fd, id, result);
}

/* Simple JSON-RPC parser (handles basic MCP requests) */
static void handle_mcp_request(int client_fd, const char *request) {
    /* Very basic parsing - in production, use a proper JSON library */
    char method[128] = {0};
    char id[64] = "null";
    char tool_name[128] = {0};

    /* Extract method */
    const char *method_start = strstr(request, "\"method\"");
    if (method_start) {
        sscanf(method_start, "\"method\":\"%127[^\"]\"", method);
    }

    /* Extract id */
    const char *id_start = strstr(request, "\"id\"");
    if (id_start) {
        sscanf(id_start, "\"id\":\"%63[^\"]\"", id);
        if (strlen(id) == 0) {
            /* Try numeric id */
            sscanf(id_start, "\"id\":%63[^,}]", id);
        }
    }

    log_debug("MCP request: method=%s, id=%s", method, id);

    if (strcmp(method, "tools/list") == 0) {
        handle_tools_list(client_fd, id);
    } else if (strcmp(method, "tools/call") == 0) {
        /* Extract tool name from params */
        const char *name_start = strstr(request, "\"name\"");
        if (name_start) {
            sscanf(name_start, "\"name\":\"%127[^\"]\"", tool_name);
            handle_tools_call(client_fd, id, tool_name);
        } else {
            send_mcp_error(client_fd, id, -32602, "Missing tool name");
        }
    } else if (strcmp(method, "initialize") == 0) {
        const char *init_result =
            "{\"protocolVersion\":\"2024-11-05\","
            "\"capabilities\":{\"tools\":{}},\"serverInfo\":{"
            "\"name\":\"v6-gatewayd-mcp\",\"version\":\"" VERSION "\"}}";
        send_mcp_response(client_fd, id, init_result);
    } else {
        send_mcp_error(client_fd, id, -32601, "Method not found");
    }
}

int mcp_init(const mcp_config_t *config) {
    if (!config->enabled) {
        log_info("MCP server disabled");
        return 0;
    }

    log_info("Initializing MCP server on %s", config->socket_path);

    if (config->socket_path) {
        snprintf(mcp_socket_path, sizeof(mcp_socket_path), "%s", config->socket_path);
    }

    /* Remove old socket if exists */
    unlink(mcp_socket_path);

    mcp_sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (mcp_sockfd < 0) {
        log_error("Failed to create MCP Unix socket");
        return -1;
    }

    /* Set non-blocking */
    int flags = fcntl(mcp_sockfd, F_GETFL, 0);
    fcntl(mcp_sockfd, F_SETFL, flags | O_NONBLOCK);

    /* Bind to Unix socket */
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, mcp_socket_path, sizeof(addr.sun_path) - 1);

    if (bind(mcp_sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        log_error("Failed to bind MCP socket: %s", strerror(errno));
        close(mcp_sockfd);
        return -1;
    }

    /* Set socket permissions (local only) */
    chmod(mcp_socket_path, 0600);

    /* Listen */
    if (listen(mcp_sockfd, 5) < 0) {
        log_error("Failed to listen on MCP socket");
        close(mcp_sockfd);
        return -1;
    }

    log_info("MCP server initialized successfully");
    return 0;
}

int mcp_start(void) {
    if (mcp_sockfd < 0) return 0;
    log_info("MCP server started");
    return 0;
}

int mcp_process(void) {
    if (mcp_sockfd < 0) {
        return 0;
    }

    struct sockaddr_un client_addr;
    socklen_t client_len = sizeof(client_addr);

    int client_fd = accept(mcp_sockfd, (struct sockaddr*)&client_addr, &client_len);
    if (client_fd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            log_error("MCP accept() failed: %s", strerror(errno));
        }
        return 0;
    }

    /* Read request */
    char request[4096];
    ssize_t n = recv(client_fd, request, sizeof(request) - 1, 0);
    if (n > 0) {
        request[n] = '\0';
        handle_mcp_request(client_fd, request);
    }

    close(client_fd);
    return 0;
}

void mcp_stop(void) {
    if (mcp_sockfd >= 0) {
        log_info("Stopping MCP server");
        close(mcp_sockfd);
        unlink(mcp_socket_path);
        mcp_sockfd = -1;
    }
}

void mcp_cleanup(void) {
    mcp_stop();
}
