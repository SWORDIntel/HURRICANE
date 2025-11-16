/*
 * MCP (Model Context Protocol) server interface
 * Local-only interface for AI access to IPv6 gateway
 */

#ifndef MCP_H
#define MCP_H

#include "v6gw.h"

/* MCP server configuration */
typedef struct {
    const char *socket_path;  /* Unix socket path for local-only access */
    bool enabled;
} mcp_config_t;

/* Initialize MCP server */
int mcp_init(const mcp_config_t *config);

/* Start MCP server (non-blocking) */
int mcp_start(void);

/* Stop MCP server */
void mcp_stop(void);

/* Process MCP requests (call in main loop) */
int mcp_process(void);

/* Cleanup MCP server */
void mcp_cleanup(void);

#endif /* MCP_H */
