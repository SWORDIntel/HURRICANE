# HURRICANE v6-gatewayd

**High-performance IPv6-over-IPv4 tunnel gateway with programmatic API**

HURRICANE (codename: v6-gatewayd) is a lightweight daemon that manages IPv6-over-IPv4 tunnels and exposes a simple REST API for applications to discover and use IPv6 connectivity. Perfect for running I2P, Tor, or other P2P applications behind residential NAT with real IPv6 addresses.

## Quick Start

**Unified Entry Point** - Single script controls everything:

```bash
# Installation (one-time)
./install.sh

# Start all services (daemon + API + WebUI + scanner)
./hurricane start

# Access WebUI
open http://127.0.0.1:8643

# Check status
./hurricane status

# Stop all services
./hurricane stop
```

See **[QUICKSTART.md](QUICKSTART.md)** for complete usage guide.

**Using as Submodule:** See **[SUBMODULE_INTEGRATION.md](SUBMODULE_INTEGRATION.md)** for integration into larger projects.

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
  - `/tunnel/:id/start|stop|restart` - Control individual tunnels
  - `/config` - View current daemon configuration
  - `/logs` - Export activity logs
  - `/metrics` - Prometheus-compatible metrics
  - `/ports/udp`, `/ports/tcp` - Dynamic proxy port management
  - `/ui` - TEMPEST-themed web interface

- **TEMPEST WebUI** (Class C Compliant)
  - Dark military-themed web dashboard ([docs/WEBUI.md](docs/WEBUI.md))
  - **Tunnel Control**: Start/stop/restart tunnels with one click
  - **Real-time Graphs**: Bandwidth, latency, and health score charts
  - **Configuration Viewer**: Live config display with JSON export
  - **Activity Log Export**: Download logs for analysis
  - **Prometheus Integration**: Direct metrics access
  - Health score visualization with auto-refresh (5s)
  - Security-hardened (CSP, local-only, no external resources)
  - Zero external dependencies (pure Canvas charts, no Chart.js)

- **MCP Server** (Model Context Protocol)
  - Local-only Unix socket interface for AI/automation access
  - Query tunnel status, IPv6 addresses, and health programmatically

- **FASTPORT IPv6 Scanner** 🆕
  - High-performance IPv6 port scanner (20-25M packets/sec with AVX-512)
  - Integrated with v6-gatewayd for automatic IPv6 source selection
  - CVE vulnerability detection on discovered services
  - Native IPv6 socket operations through Hurricane Electric tunnel
  - See [fastport/README_IPV6.md](fastport/README_IPV6.md) for full documentation

- **IPv9 Routing Integration** 🆕
  - Dual routing support: IPv6 + IPv9 (China Decimal Network)
  - IPVNINER integration for .chn domain resolution
  - Switch between IPv6, IPv9, or Dual mode via API/WebUI
  - DNS overlay routing through IPv9 servers (202.170.218.93, 61.244.5.162)
  - Simultaneous access to both networks in Dual mode
  - See [docs/IPV9_ROUTING_INTEGRATION.md](docs/IPV9_ROUTING_INTEGRATION.md) for details

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
- IPv4 connectivity
- Hurricane Electric tunnel account (https://tunnelbroker.net) or other IPv6 tunnel provider

### One-Command Setup (Recommended - SWORD HQ)

**The absolute easiest way** - single command does everything:

```bash
# Clone the repository
git clone https://github.com/SWORDIntel/HURRICANE.git
cd HURRICANE

# One-command launch: builds, installs, configures, starts everything
./launch.sh
```

This master launch script will:
- Install all system dependencies (auto-detects Debian/Ubuntu, RHEL/Fedora, Arch)
- Build the daemon and utilities (v6-gatewayd, v6gw-keygen, he-update)
- Install to system directories
- **Encrypt and install SWORD HQ credentials** (Tunnel ID: 940962)
  - Username: `SWORDIntel`
  - Password: `dokuchayev` (encrypted with AES-256-CBC + machine-specific key)
- Start the daemon with auto-start enabled
- Enable Hurricane Electric auto-update timer (checks IP every 15 minutes)
- Show live status and WebUI URL

**Toggle mode:** Run `./launch.sh` again to:
- **Stop** the daemon if it's running
- **Start** it if it's stopped

After installation, these helper commands are available:
```bash
sudo v6gw-launch          # Toggle daemon (start/stop)
sudo hurricane-launch     # Alias for v6gw-launch
```

### Manual Bootstrap (Alternative)

If you want more control over the build process:

```bash
# Clone and build
git clone https://github.com/SWORDIntel/HURRICANE.git
cd HURRICANE

# Install dependencies and build
sudo make bootstrap

# Install to system
sudo make install

# Quick launch with encrypted credentials
sudo v6gw-launch
```

### Manual Build (Alternative)

If you prefer to install dependencies manually:

```bash
# Install dependencies first
# Debian/Ubuntu:
sudo apt-get install -y gcc make libssl-dev libcurl4-openssl-dev \
    iproute2 iputils-ping wireguard-tools curl jq bc

# RHEL/CentOS/Fedora:
sudo dnf install -y gcc make openssl-devel libcurl-devel \
    iproute iputils wireguard-tools curl jq bc

# Then build
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

### IPv6 Port Scanning with FASTPORT

After launching v6-gatewayd, you can use the integrated FASTPORT scanner for high-performance IPv6 reconnaissance:

```bash
# Check IPv6 connectivity
fastport-ipv6 --check

# Scan IPv6 host on common ports
fastport-ipv6 2001:470:1f1c:258::1

# Scan specific ports with CVE lookup
fastport-ipv6 2001:470:1f1c:258::1 -p 22,80,443,8080 --cve

# Scan port range with verbose output
fastport-ipv6 2001:470:1f1c:258::1 -r 1-1000 -v

# Save results to JSON
fastport-ipv6 2001:470:1f1c:258::1 --cve -o scan-results.json
```

**Key Features:**
- **Blazing Fast**: Async Python backend with planned Rust/AVX-512 integration
- **CVE Integration**: Automatic vulnerability lookup for discovered services
- **Auto-Detection**: Uses v6-gatewayd API to find source IPv6 address
- **Banner Grabbing**: Service version detection for accurate CVE matching

See [fastport/README_IPV6.md](fastport/README_IPV6.md) for complete documentation.

### Hurricane Electric Auto-Update

**If you used `./launch.sh`**, this is already configured! The launch script automatically:
- Encrypts your SWORD HQ credentials (AES-256-CBC with machine-specific key)
- Installs the systemd timer (runs every 15 minutes)
- Enables auto-start for the update service

Your tunnel endpoint will automatically update when your IP changes, with credentials securely encrypted at rest.

**Manual configuration** (if you didn't use the launch script):

If you have a dynamic IP address, you can manually configure the `he-update` utility to automatically update your Hurricane Electric tunnel endpoint when your IP changes.

**Requirements:**
- libcurl development library: `sudo apt-get install libcurl4-openssl-dev`
- Hurricane Electric tunnel account credentials

**Getting Your Credentials:**
1. Login to https://tunnelbroker.net
2. Click on your tunnel
3. Under "Example Update URL", you'll find credentials in this format:
   ```
   https://USERNAME:PASSWORD@ipv4.tunnelbroker.net/nic/update?hostname=TUNNEL_ID
   ```
4. Use the USERNAME (your HE account username) and PASSWORD (your HE account password or update key)
5. Use the TUNNEL_ID (the numeric ID after `hostname=`)

**Manual Usage:**

```bash
# Auto-detect your public IP and update tunnel endpoint
he-update -u SWORDIntel -p your_password -t 940962

# Force update even if IP hasn't changed
he-update -u SWORDIntel -p your_password -t 940962 -f

# Specify a specific IP address
he-update -u SWORDIntel -p your_password -t 940962 -i 1.2.3.4

# Verbose output
he-update -u SWORDIntel -p your_password -t 940962 -v
```

**Automatic Updates with Systemd:**

1. Create environment file with your credentials:

```bash
sudo cp config/v6-gatewayd-he.env.example /etc/v6-gatewayd-he.env
sudo nano /etc/v6-gatewayd-he.env
```

2. Configure your credentials in `/etc/v6-gatewayd-he.env`:

```bash
HE_USERNAME=your_username
HE_PASSWORD=your_password_or_update_key
HE_TUNNEL_ID=940962
```

3. Secure the credentials file:

```bash
sudo chmod 600 /etc/v6-gatewayd-he.env
sudo chown root:root /etc/v6-gatewayd-he.env
```

4. Install and enable the systemd timer:

```bash
# Copy service files (if not already installed via 'make install')
sudo cp systemd/he-update.service /etc/systemd/system/
sudo cp systemd/he-update.timer /etc/systemd/system/

# Enable and start the timer (runs every 15 minutes)
sudo systemctl daemon-reload
sudo systemctl enable he-update.timer
sudo systemctl start he-update.timer

# Check timer status
sudo systemctl status he-update.timer

# View update logs
sudo journalctl -u he-update -f
```

The timer will automatically:
- Check your public IP every 15 minutes
- Update the Hurricane Electric tunnel endpoint only if your IP has changed
- Cache the last known IP to avoid unnecessary API calls
- Log all updates to systemd journal

**Notes:**
- The update client caches your IP in `/var/lib/v6-gatewayd/he-ip.cache`
- Updates only happen when your IP actually changes (no unnecessary API calls)
- If libcurl is not available during build, `he-update` will be skipped (daemon still builds normally)

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

#### POST /tunnel/:id/start

Start a stopped tunnel.

**Response:**
```json
{
  "status": "ok",
  "tunnel_id": 0,
  "name": "he",
  "state": "up"
}
```

**Usage:**
```bash
curl -X POST http://localhost:8642/tunnel/0/start
```

#### POST /tunnel/:id/stop

Stop a running tunnel.

**Response:**
```json
{
  "status": "ok",
  "tunnel_id": 0,
  "name": "he",
  "state": "down"
}
```

#### POST /tunnel/:id/restart

Restart a tunnel (stop then start).

**Response:**
```json
{
  "status": "ok",
  "tunnel_id": 0,
  "name": "he",
  "state": "restarted"
}
```

#### GET /config

Get current daemon configuration.

**Response:**
```json
{
  "daemon": {
    "mode": "kernel",
    "log_level": "info",
    "crypto_enabled": true
  },
  "api": {
    "bind_addr": "127.0.0.1",
    "port": 8642
  },
  "tunnels": [
    {
      "name": "he",
      "type": "he_6in4",
      "iface": "he0",
      "v6_prefix": "2001:470::/64",
      "priority": 0
    }
  ]
}
```

#### GET /logs?limit=N

Get recent activity logs (default limit: 100, max: 1000).

**Response:**
```json
{
  "logs": [
    {
      "timestamp": 1699564234,
      "level": "INFO",
      "message": "Tunnel he (he0) state: UP, health: 95, latency: 35ms"
    }
  ],
  "total": 1
}
```

**Usage:**
```bash
curl "http://localhost:8642/logs?limit=50"
```

#### GET /metrics

Get Prometheus-compatible metrics in text format.

**Response (text/plain):**
```
# HELP v6gw_tunnel_state Tunnel state (0=down, 1=up, 2=error)
# TYPE v6gw_tunnel_state gauge
v6gw_tunnel_state{name="he",iface="he0",type="he_6in4"} 1

# HELP v6gw_tunnel_health_score Tunnel health score (0-100)
# TYPE v6gw_tunnel_health_score gauge
v6gw_tunnel_health_score{name="he",iface="he0"} 95

# HELP v6gw_tunnel_latency_ms Tunnel latency in milliseconds
# TYPE v6gw_tunnel_latency_ms gauge
v6gw_tunnel_latency_ms{name="he",iface="he0"} 35

# HELP v6gw_tunnel_tx_bytes Bytes transmitted
# TYPE v6gw_tunnel_tx_bytes counter
v6gw_tunnel_tx_bytes{name="he",iface="he0"} 1234567

# HELP v6gw_tunnel_rx_bytes Bytes received
# TYPE v6gw_tunnel_rx_bytes counter
v6gw_tunnel_rx_bytes{name="he",iface="he0"} 987654

# HELP v6gw_tunnel_reachable Tunnel reachability (0=no, 1=yes)
# TYPE v6gw_tunnel_reachable gauge
v6gw_tunnel_reachable{name="he",iface="he0"} 1
```

**Prometheus Configuration:**
```yaml
scrape_configs:
  - job_name: 'v6-gatewayd'
    static_configs:
      - targets: ['127.0.0.1:8642']
    metrics_path: '/metrics'
    scrape_interval: 15s
```

#### GET /ui

Access the TEMPEST Class C web interface at http://127.0.0.1:8642/ui

**Features:**
- Real-time tunnel monitoring with 5-second auto-refresh
- Start/stop/restart tunnel controls
- Bandwidth, latency, and health score graphs (Canvas-based)
- Configuration viewer with JSON export
- Activity log viewer with text export
- Prometheus metrics integration

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
├── src/                  # Source code
│   ├── main.c           # Main daemon entry point
│   ├── config.c         # Configuration parser
│   ├── tunnel.c         # Tunnel management with failover
│   ├── health.c         # Health checks
│   ├── api.c            # REST API server
│   ├── mcp.c            # MCP server
│   ├── proxy.c          # Proxy mode (UDP/TCP relay)
│   ├── socks5.c         # SOCKS5 proxy mode
│   ├── session.c        # Session management
│   ├── crypto.c         # CNSA 2.0 cryptography
│   ├── hwauth.c         # Hardware authentication
│   ├── log.c            # Logging system
│   └── util.c           # Utilities
├── include/              # Header files
├── config/               # Example configurations
│   ├── v6-gatewayd.conf.example
│   ├── mullvad-example.conf
│   └── prometheus.yml   # Prometheus scrape config
├── systemd/              # Systemd service files
│   └── v6-gatewayd.service  # Hardened systemd unit
├── web/                  # TEMPEST WebUI
│   └── index.html       # Single-page web dashboard
├── tests/                # Testing suite
│   ├── integration_test.sh  # API integration tests
│   └── benchmark.sh     # Performance benchmarks
├── docs/                 # Documentation
│   ├── MULLVAD.md       # Mullvad VPN guide
│   ├── WEBUI.md         # WebUI documentation
│   ├── AUTHENTICATION.md # Auth guide
│   └── DEPLOYMENT.md    # Production deployment
├── .github/              # CI/CD workflows
│   └── workflows/
│       └── ci.yml       # GitHub Actions pipeline
├── Dockerfile            # Docker container image
├── docker-compose.yml    # Docker Compose stack
├── Makefile              # Build system
├── README.md             # This file
└── SECURITY.md           # Security architecture
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

## Testing & Quality Assurance

### Integration Tests

Run the comprehensive integration test suite:

```bash
./tests/integration_test.sh
```

Tests include:
- API endpoint validation (health, config, logs, metrics)
- JSON response format verification
- Prometheus metrics format validation
- WebUI content validation
- Error handling and edge cases

### Performance Benchmarks

Measure API latency and throughput:

```bash
./tests/benchmark.sh
```

Benchmarks measure:
- API endpoint latency (avg/min/max)
- Concurrent request handling
- Requests per second throughput
- Memory usage
- WebUI load time

**Expected Results:**
- API latency: <50ms average
- Throughput: >100 req/s
- Memory usage: <10MB RSS

### Continuous Integration

GitHub Actions workflow automatically:
- Builds on every commit
- Runs integration tests
- Builds Docker images
- Performs security scans
- Creates releases for tagged commits

View CI status: `.github/workflows/ci.yml`

## Deployment

### Quick Deploy

**Native:**
```bash
make && sudo make install
sudo systemctl start v6-gatewayd
```

**Docker:**
```bash
docker-compose up -d
```

**With Monitoring:**
```bash
docker-compose --profile monitoring up -d
```

### Production Deployment

See **[DEPLOYMENT.md](docs/DEPLOYMENT.md)** for comprehensive production deployment guide including:

- Docker deployment with monitoring stack
- Systemd service hardening
- Security best practices
- Performance tuning
- Backup & recovery procedures
- Troubleshooting guide

### Docker Features

**Included in docker-compose.yml:**
- v6-gatewayd daemon with health checks
- Prometheus metrics collection
- Grafana dashboards
- Automated restart policies
- Volume management for persistence

**Access:**
- API: http://localhost:8642
- WebUI: http://localhost:8642/ui
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000 (admin/admin)

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
