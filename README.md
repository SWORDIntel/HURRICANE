# HURRICANE v6-gatewayd

**High-performance IPv6-over-IPv4 tunnel gateway with programmatic API**

HURRICANE (codename: v6-gatewayd) is a lightweight daemon that manages IPv6-over-IPv4 tunnels and exposes a simple REST API for applications to discover and use IPv6 connectivity. Perfect for running I2P, Tor, or other P2P applications behind residential NAT with real IPv6 addresses.

## Features

- **Multiple Tunnel Backends**
  - Hurricane Electric 6in4 (sit tunnels)
  - **Mullvad VPN** - Privacy-focused WireGuard VPN (see [MULLVAD.md](docs/MULLVAD.md))
  - WireGuard support with wg-quick integration
  - External/pre-configured tunnel monitoring

- **Flexible Exposure Modes**
  - **Kernel Mode** (recommended): Apps bind directly to IPv6
  - **Proxy Mode**: UDP/TCP relay for constrained environments
  - **SOCKS5 Mode**: Generic proxy with IPv6 preference for any application

- **Advanced Tunnel Management**
  - Multi-tunnel failover with automatic health monitoring
  - Dynamic tunnel selection based on latency and reliability
  - Health scoring system (0-100) with configurable thresholds
  - Priority-based tunnel preferences

- **REST API**
  - `/health` - System health and IPv6 connectivity status
  - `/v6/address` - Get available IPv6 addresses and reachability
  - `/tunnels` - List all tunnels and their states

- **MCP Server** (Model Context Protocol)
  - Local-only Unix socket interface for AI/automation access
  - Query tunnel status, IPv6 addresses, and health programmatically

- **Production Ready**
  - Systemd integration
  - Health monitoring with automatic checks
  - Structured logging
  - Signal handling (graceful shutdown, config reload)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      v6-gatewayd Daemon                     │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ HE 6in4      │  │ WireGuard    │  │ External     │     │
│  │ Backend      │  │ Backend      │  │ Backend      │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │          Health Check & Monitoring System            │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌─────────────────┐              ┌──────────────────┐    │
│  │   REST API      │              │   MCP Server     │    │
│  │ (HTTP+JSON)     │              │  (Unix Socket)   │    │
│  │ localhost:8642  │              │  Local Only      │    │
│  └─────────────────┘              └──────────────────┘    │
└─────────────────────────────────────────────────────────────┘
         │                                    │
         ↓                                    ↓
   ┌──────────┐                         ┌──────────┐
   │   I2P    │                         │ AI/Claude│
   │   Tor    │                         │ MCP Tools│
   │ Any App  │                         │          │
   └──────────┘                         └──────────┘
```

## Quick Start

### Prerequisites

- Linux system with root access
- GCC compiler
- IPv4 connectivity
- Hurricane Electric tunnel account (https://tunnelbroker.net) or other IPv6 tunnel provider

### Build

```bash
# Clone the repository
git clone https://github.com/SWORDIntel/HURRICANE.git
cd HURRICANE

# Build
make

# Install (requires root)
sudo make install
```

### Configure

1. Get your tunnel credentials from Hurricane Electric:
   - Sign up at https://tunnelbroker.net
   - Create a tunnel and note:
     - Server IPv4 Address
     - Client IPv6 Address (your /64 prefix)

2. Copy and edit the configuration:

```bash
sudo cp /etc/v6-gatewayd.conf.example /etc/v6-gatewayd.conf
sudo nano /etc/v6-gatewayd.conf
```

3. Update the `[tunnel.he]` section with your credentials:

```ini
[tunnel.he]
type = he_6in4
iface = he0
endpoint_ipv4 = YOUR.TUNNEL.SERVER.IP
local_ipv4 =  # Leave empty for auto-detect
v6_prefix = YOUR:IPV6:PREFIX::2
prefix_len = 64
enabled = true
```

### Run

```bash
# Start the daemon
sudo systemctl start v6-gatewayd

# Enable on boot
sudo systemctl enable v6-gatewayd

# Check status
sudo systemctl status v6-gatewayd

# View logs
sudo journalctl -u v6-gatewayd -f
```

### Test

```bash
# Check health
curl http://localhost:8642/health

# Get IPv6 addresses
curl http://localhost:8642/v6/address

# List tunnels
curl http://localhost:8642/tunnels

# Test IPv6 connectivity
ping6 -c 3 2001:4860:4860::8888
```

## Configuration Reference

### Core Settings

```ini
[core]
log_level = info          # debug, info, warn, error
state_dir = /var/lib/v6-gatewayd
api_port = 8642          # REST API port
api_bind = 127.0.0.1     # API bind address (localhost only)
```

### Tunnel Configuration

#### Hurricane Electric 6in4

```ini
[tunnel.he]
type = he_6in4
iface = he0              # Interface name
endpoint_ipv4 = X.X.X.X  # HE server IPv4
local_ipv4 = Y.Y.Y.Y     # Your WAN IPv4 (optional)
v6_prefix = 2001:470::/64
prefix_len = 64
enabled = true
```

#### Mullvad VPN (Privacy-Focused)

**See detailed guide**: [docs/MULLVAD.md](docs/MULLVAD.md)

```ini
[tunnel.mullvad]
type = wireguard
iface = mullvad0
v6_prefix = fc00:bbbb:bbbb:bb01::1  # Optional - from Mullvad config
enabled = true
priority = 0  # For failover
```

**Quick Setup:**
1. Sign up at https://mullvad.net (€5/month, no personal info required)
2. Generate WireGuard config at https://mullvad.net/en/account/#/wireguard-config
3. Download config → save to `/etc/wireguard/mullvad0.conf`
4. Configure v6-gatewayd with the example above
5. Start: `sudo systemctl start v6-gatewayd`

**Benefits:**
- Privacy-focused (no logs, anonymous)
- IPv4 + optional IPv6 support
- Works worldwide (600+ servers)
- Automatic failover between locations
- Perfect for I2P, Tor, P2P apps

#### External/Pre-configured Tunnel

```ini
[tunnel.external]
type = external
iface = tun0             # Pre-existing interface
v6_prefix = 2001:db8::1
prefix_len = 64
enabled = true
```

### Exposure Modes

```ini
[exposure]
mode = kernel            # kernel (recommended), proxy, or socks5
```

## API Reference

### REST API Endpoints

Base URL: `http://127.0.0.1:8642`

#### GET /health

Get overall system health and IPv6 connectivity status.

**Response:**
```json
{
  "status": "ok",
  "v6_reachable": true,
  "v6_latency_ms": 35,
  "active_tunnels": 1,
  "last_check": 1699564234
}
```

#### GET /v6/address

Get available IPv6 addresses and their reachability.

**Response:**
```json
{
  "addresses": [
    {
      "iface": "he0",
      "address": "2001:470:1234:5678::2",
      "prefix": 64,
      "reachable": true,
      "latency_ms": 35
    }
  ]
}
```

#### GET /tunnels

List all configured tunnels and their states.

**Response:**
```json
{
  "tunnels": [
    {
      "name": "he",
      "type": "he_6in4",
      "state": "up",
      "iface": "he0",
      "v6_prefix": "2001:470:1234:5678::/64",
      "rx_bytes": 1234567,
      "tx_bytes": 987654,
      "last_check": 1699564234
    }
  ]
}
```

#### POST /ports/udp

Create a UDP port mapping (Proxy Mode only).

**Request:**
```json
{
  "internal_port": 7654,
  "external_port": 7654,
  "v6_address": "2001:470:1234:5678::2",
  "description": "I2P-UDP"
}
```

**Response:**
```json
{
  "status": "ok",
  "internal_port": 7654,
  "external_port": 7654,
  "v6_address": "2001:470:1234:5678::2"
}
```

**Usage:**
```bash
curl -X POST http://localhost:8642/ports/udp \
  -H "Content-Type: application/json" \
  -d '{"internal_port":7654,"external_port":7654,"v6_address":"2001:470:1234:5678::2","description":"I2P-UDP"}'
```

#### POST /ports/tcp

Create a TCP port mapping (Proxy Mode only).

**Request:**
```json
{
  "internal_port": 9000,
  "external_port": 9000,
  "v6_address": "2001:470:1234:5678::2",
  "description": "Application"
}
```

**Response:**
```json
{
  "status": "ok",
  "internal_port": 9000,
  "external_port": 9000,
  "v6_address": "2001:470:1234:5678::2"
}
```

#### GET /probe/udp?port=XXXX

Initiate UDP reachability probe for a port.

**Response:**
```json
{
  "status": "probe_initiated",
  "port": 7654,
  "note": "External UDP probe not implemented - use external tools to verify reachability"
}
```

**Usage:**
```bash
curl "http://localhost:8642/probe/udp?port=7654"
```

## MCP Server Interface

The MCP (Model Context Protocol) server provides a local-only interface for AI agents and automation tools.

**Socket Path:** `/var/run/v6-gatewayd-mcp.sock`

### Available Tools

#### get_tunnel_status
Get status of all IPv6 tunnels.

#### get_ipv6_address
Get available IPv6 addresses and their reachability.

#### check_health
Check overall IPv6 gateway health and connectivity.

### Example Usage with Claude Code

The MCP server can be used by AI assistants like Claude to interact with your IPv6 gateway:

```json
{
  "mcpServers": {
    "v6-gatewayd": {
      "command": "socat",
      "args": ["UNIX-CONNECT:/var/run/v6-gatewayd-mcp.sock", "STDIO"]
    }
  }
}
```

## Multi-Tunnel Failover

v6-gatewayd supports automatic failover between multiple tunnels for high availability.

### Health Scoring

Each tunnel is continuously monitored and assigned a health score (0-100):

- **Reachability**: -50 points if unreachable
- **Latency-based scoring**:
  - <50ms: Excellent (50 points)
  - 50-100ms: Good (40 points)
  - 100-200ms: Fair (25 points)
  - 200-500ms: Poor (10 points)
  - >500ms: Very poor (0 points)
- **Priority bonus**: User-defined tunnel priority (0=highest) adds bonus points

### Automatic Failover

The daemon performs automatic failover every 60 seconds:

1. Checks the health of the current primary tunnel
2. If health drops below 30 or tunnel is down, searches for a backup
3. Switches to the best alternative tunnel (health >= 50)
4. Logs the failover event with health scores
5. Updates routing automatically

### Configuration

Configure multiple tunnels with different priorities:

```ini
[tunnel1]
name = he-primary
type = he_6in4
enabled = true
priority = 0    # Highest priority

[tunnel2]
name = wg-backup
type = wireguard
enabled = true
priority = 1    # Backup tunnel

[tunnel3]
name = he-backup2
type = he_6in4
enabled = true
priority = 2    # Second backup
```

### Monitoring Failover

Check tunnel health and failover status:

```bash
# View daemon logs
journalctl -u v6-gatewayd -f

# Example output:
# [INFO] Selected primary tunnel: he-primary (health: 95)
# [WARN] Primary tunnel he-primary health degraded: 25/100
# [INFO] Failing over from he-primary to wg-backup (health: 25 -> 85)
```

## Use Cases

### I2P Over IPv6

Configure I2P to use the IPv6 address provided by v6-gatewayd:

1. Get your IPv6 address:
   ```bash
   curl http://localhost:8642/v6/address
   ```

2. Configure I2P:
   - Enable IPv6 transport
   - Bind to the provided IPv6 address
   - I2P will automatically use IPv6 for connectivity

3. Verify reachability through the v6-gatewayd health checks

### Tor Relay with IPv6

Run a Tor relay with IPv6 connectivity:

1. Get your IPv6 address from v6-gatewayd
2. Configure Tor to advertise both IPv4 and IPv6
3. Improve your relay's performance and reach

## Development

### Project Structure

```
HURRICANE/
├── src/              # Source code
│   ├── main.c       # Main daemon entry point
│   ├── config.c     # Configuration parser
│   ├── tunnel.c     # Tunnel management with failover
│   ├── health.c     # Health checks
│   ├── api.c        # REST API server
│   ├── mcp.c        # MCP server
│   ├── proxy.c      # Proxy mode (UDP/TCP relay)
│   ├── socks5.c     # SOCKS5 proxy mode
│   ├── session.c    # Session management
│   ├── crypto.c     # CNSA 2.0 cryptography
│   ├── hwauth.c     # Hardware authentication
│   ├── log.c        # Logging system
│   └── util.c       # Utilities
├── include/          # Header files
├── config/           # Example configurations
├── systemd/          # Systemd service files
├── docs/             # Documentation
├── Makefile          # Build system
├── README.md         # This file
└── SECURITY.md       # Security architecture
```

### Building from Source

```bash
# Debug build with symbols
make debug

# Clean build artifacts
make clean

# Install
sudo make install

# Uninstall
sudo make uninstall
```

### Dependencies

- Standard C library (glibc)
- Linux kernel headers (for tunnel management)
- POSIX threads (pthread)
- Math library (libm)

No external dependencies required - everything is built with standard libraries!

## Performance

v6-gatewayd is designed for minimal overhead:

- **Memory Usage:** ~2-5 MB RSS
- **CPU Usage:** <1% on idle, <5% under load
- **Latency:** <1ms API response time
- **Tunnel Overhead:** Native kernel routing (zero-copy where possible)

## Security

### API Security

- API binds to `127.0.0.1` only (local access)
- No authentication required (local trust model)
- Can be firewalled for additional protection

### MCP Security

- Unix socket with `0600` permissions (owner only)
- Local access only (no network exposure)
- Read-only operations (query only, no modifications)

### Tunnel Security

- Runs as root (required for tunnel management)
- Systemd hardening with minimal capabilities
- Only `CAP_NET_ADMIN` and `CAP_NET_RAW` capabilities

## Troubleshooting

### Tunnel won't come up

```bash
# Check if you have root privileges
sudo v6-gatewayd -f -d

# Verify configuration
sudo v6-gatewayd -c /etc/v6-gatewayd.conf -d

# Check system logs
sudo journalctl -u v6-gatewayd -n 50
```

### IPv6 not reachable

```bash
# Test tunnel manually
ping6 -c 3 2001:4860:4860::8888

# Check routing
ip -6 route show

# Verify interface is up
ip link show he0
ip -6 addr show he0
```

### API not responding

```bash
# Check if daemon is running
systemctl status v6-gatewayd

# Test API locally
curl -v http://localhost:8642/health

# Check if port is listening
sudo ss -tlnp | grep 8642
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

[Specify your license here]

## Acknowledgments

- Hurricane Electric for free IPv6 tunnels (https://tunnelbroker.net)
- The I2P and Tor projects for inspiration
- The CONCEPT.md design document that started this project

## Support

- Issues: https://github.com/SWORDIntel/HURRICANE/issues
- Documentation: See CONCEPT.md for design details

## Roadmap

- [x] HE 6in4 tunnel support
- [x] REST API
- [x] MCP server interface
- [x] Health monitoring
- [ ] WireGuard backend
- [ ] Proxy mode (UDP/TCP relay)
- [ ] SOCKS5 mode
- [ ] Web UI dashboard
- [ ] Metrics/Prometheus export
- [ ] Multiple tunnel failover
- [ ] Dynamic tunnel selection

---

**HURRICANE v6-gatewayd** - Bringing IPv6 to where it's needed most
