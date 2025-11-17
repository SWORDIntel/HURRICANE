# HURRICANE v6-gatewayd Quick Start Guide

Complete IPv6 tunnel gateway with routing control, split tunneling, and port scanning.

## Unified Entry Points

HURRICANE now provides simple, unified commands for installation and operation:

### Installation (One-Time Setup)

```bash
# Run the unified installation script
./install.sh

# OR use make
make setup
```

This will:
- Install all system dependencies (gcc, python3, rust, etc.)
- Initialize git submodules (IPVNINER)
- Build FASTPORT scanner
- Install hurricane control script
- Set up all necessary directories

### Starting the System

```bash
# Start all services
./hurricane start

# OR use make
make start
```

This starts:
- v6-gatewayd daemon (port 8642)
- Comprehensive API server (port 8643)
- Routing controller (IPv6/IPv9/Dual)
- Split tunneling manager
- FASTPORT unified scanner
- WebUI interface

### Stopping the System

```bash
# Stop all services
./hurricane stop

# OR use make
make stop
```

### Checking Status

```bash
# View service status
./hurricane status

# OR use make
make status
```

### Restarting

```bash
# Restart all services
./hurricane restart

# OR use make
make restart
```

### Viewing Logs

```bash
# View all logs
./hurricane logs

# View specific service logs
./hurricane logs daemon
./hurricane logs api
```

## Access Points

Once started, access the system at:

| Service | URL | Description |
|---------|-----|-------------|
| **WebUI** | http://127.0.0.1:8643 | Complete web interface |
| **Comprehensive API** | http://127.0.0.1:8643 | Unified API endpoint |
| **Daemon API** | http://127.0.0.1:8642 | Direct daemon access |
| **Prometheus Metrics** | http://127.0.0.1:8642/metrics | Monitoring endpoint |

## WebUI Features

The WebUI at port 8643 provides:

### 1. Routing Mode Control
- **IPv6 Only**: Route all traffic through IPv6 tunnels
- **IPv9 Only**: Route all traffic through IPv9 network (China decimal network)
- **Dual Mode**: Access both IPv6 and IPv9 simultaneously

### 2. Split Tunneling Rules
- Add domain-based routing rules
- Pattern matching: `*.chn` routes to IPv9, `*.google.com` to IPv6
- Priority-based rule evaluation
- Enable/disable rules on the fly

### 3. FASTPORT Unified Scanner
- Scan IPv6, IPv4, and IPv9 (.chn domains) targets
- Real-time progress updates via Server-Sent Events
- Service detection and banner grabbing
- Shows which route (IPv6/IPv9) was used for each port

### 4. System Monitoring
- Tunnel health and status
- Bandwidth graphs
- Latency monitoring
- Activity logs

## Configuration

### Tunnel Configuration

Edit tunnel configs in `config/tunnels/`:

```toml
# config/tunnels/940962.toml
[tunnel]
name = "he-940962"
type = "6in4"
enabled = true
priority = 100

[ipv4]
local = "0.0.0.0"
remote = "216.66.80.98"

[ipv6]
local = "2001:470:1f1c:258::2"
remote = "2001:470:1f1c:258::1"
prefix = "2001:470:1f1d:258::/64"
```

### Credentials (Hurricane Electric)

Store credentials in `config/credentials/`:

```bash
# config/credentials/940962.creds
SWORDIntel:your_update_key
```

## Command Reference

### Hurricane Control Script

```bash
hurricane <command> [options]

Commands:
  start              Start all HURRICANE services
  stop               Stop all HURRICANE services
  restart            Restart all HURRICANE services
  status             Show status of all services
  logs [service]     Show logs (daemon|api|all)
  help               Show help message
```

### Make Targets

```bash
make help          # Show all available targets
make setup         # Run unified installation
make start         # Start all services
make stop          # Stop all services
make restart       # Restart all services
make status        # Check service status
```

### Scanner CLI

```bash
# Scan IPv6 target
fastport-ipv6 2001:470:1f1c:258::1 -p 22,80,443

# Scan IPv9 .chn domain
fastport-unified www.v9.chn -p 80,443,8080

# Scan with custom timeout
fastport-unified example.com -p 1-1000 -t 2.0
```

### Split Tunneling CLI

```bash
# List rules
python3 scripts/split-tunnel.py list

# Add rule
python3 scripts/split-tunnel.py add "China Sites" "*.chn,*.cn" ipv9

# Test domain matching
python3 scripts/split-tunnel.py test www.v9.chn
```

### Routing Mode CLI

```bash
# Check routing status
python3 scripts/hurricane-router.py status

# Set routing mode
python3 scripts/hurricane-router.py set-mode dual

# Resolve domain
python3 scripts/hurricane-router.py resolve www.v9.chn
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    WebUI (port 8643)                        │
│  Routing Control │ Split Tunneling │ Scanner │ Monitoring  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              Comprehensive API (port 8643)                  │
│  • Routing mode management (IPv6/IPv9/Dual)                │
│  • Split tunnel rules (pattern matching)                    │
│  • FASTPORT scanner (IPv6/IPv9 with SSE)                   │
│  • Proxy to v6-gatewayd daemon                             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              v6-gatewayd Daemon (port 8642)                 │
│  • IPv6 tunnel management (6in4, WireGuard, GRE)          │
│  • Health monitoring and metrics                            │
│  • Configuration API                                        │
│  • Prometheus metrics export                                │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌──────────┴──────────┐
                    ▼                     ▼
          ┌──────────────────┐  ┌──────────────────┐
          │  IPv6 Network    │  │  IPv9 Network    │
          │  (Hurricane      │  │  (China Decimal  │
          │   Electric)      │  │   Network)       │
          └──────────────────┘  └──────────────────┘
```

## Troubleshooting

### Services Won't Start

```bash
# Check logs
./hurricane logs

# Check if ports are in use
sudo netstat -tulpn | grep -E '8642|8643'

# Verify binary exists
ls -la target/release/v6-gatewayd
```

### WebUI Not Loading

```bash
# Check comprehensive API is running
curl http://127.0.0.1:8643/routing/status

# Check daemon is running
curl http://127.0.0.1:8642/health

# View API logs
tail -f logs/comprehensive-api.log
```

### Scanner Not Working

```bash
# Test IPv6 connectivity
ping6 2001:470:1f1c:258::1

# Test scanner directly
fastport-unified google.com -p 80,443

# Check scanner logs in WebUI Activity Log
```

### IPv9 Features Not Working

```bash
# Verify IPVNINER submodule
git submodule status

# Test IPv9 DNS resolution
python3 scripts/hurricane-router.py resolve www.v9.chn

# Check routing mode
python3 scripts/hurricane-router.py status
```

## Advanced Usage

### Custom Split Tunnel Rules

Priority determines evaluation order (lower = higher priority):

```bash
# High priority rule (evaluated first)
python3 scripts/split-tunnel.py add "Critical Services" "*.banking.com" ipv6 --priority 10

# Medium priority
python3 scripts/split-tunnel.py add "China Sites" "*.chn" ipv9 --priority 50

# Low priority (catch-all)
python3 scripts/split-tunnel.py add "Everything Else" "*" auto --priority 100
```

### API Integration

```python
import requests

# Set routing mode
requests.post('http://127.0.0.1:8643/routing/mode',
              json={'mode': 'dual'})

# Add split tunnel rule
requests.post('http://127.0.0.1:8643/split-tunnel/rules',
              json={
                  'name': 'My Rule',
                  'pattern': '*.example.com',
                  'route': 'ipv6',
                  'enabled': True,
                  'priority': 100
              })

# Start scan with real-time updates
scan = requests.post('http://127.0.0.1:8643/scanner/start',
                     json={
                         'target': '2001:470:1f1c:258::1',
                         'ports': '22,80,443',
                         'timeout': 1.0
                     }).json()

# Connect to SSE stream
from sseclient import SSEClient
messages = SSEClient(f'http://127.0.0.1:8643/scanner/stream/{scan["scan_id"]}')
for msg in messages:
    print(msg.data)
```

## Next Steps

1. Configure your Hurricane Electric tunnel in `config/tunnels/`
2. Add credentials in `config/credentials/`
3. Start the system: `./hurricane start`
4. Open WebUI: http://127.0.0.1:8643
5. Test with a scan of your tunnel endpoint

For detailed documentation, see:
- `README.md` - Main project documentation
- `docs/IPV9_ROUTING_INTEGRATION.md` - IPv9 routing details
- `fastport/README_IPV6.md` - FASTPORT scanner guide
