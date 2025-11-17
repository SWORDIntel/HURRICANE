# HURRICANE Submodule Integration Guide

This guide explains how to integrate HURRICANE v6-gatewayd as a submodule in larger projects.

## Overview

HURRICANE provides a complete IPv6/IPv9 tunnel gateway system that can be embedded into larger infrastructure projects as a git submodule. It offers a unified entry point (`hurricane` script) that manages all services.

## Adding HURRICANE as a Submodule

### Method 1: As a Submodule

```bash
# Navigate to your parent project
cd /path/to/your/project

# Add HURRICANE as a submodule
git submodule add https://github.com/SWORDIntel/HURRICANE.git hurricane

# Initialize submodules (including HURRICANE's own submodules)
git submodule update --init --recursive

# Commit the submodule
git add .gitmodules hurricane/
git commit -m "Add HURRICANE v6-gatewayd as submodule"
```

### Method 2: Cloning a Project with HURRICANE

```bash
# Clone your parent project with all submodules
git clone --recursive https://github.com/yourorg/yourproject.git

# OR if already cloned without --recursive
cd yourproject
git submodule update --init --recursive
```

## Directory Structure

When integrated as a submodule:

```
yourproject/
├── hurricane/                  # HURRICANE submodule
│   ├── hurricane              # Main control script
│   ├── install.sh             # Installation script
│   ├── Makefile               # Build system
│   ├── config/                # Configuration directory
│   ├── scripts/               # Python APIs and utilities
│   ├── web/                   # WebUI
│   ├── fastport/              # FASTPORT scanner
│   ├── ipvniner/              # IPv9 integration (submodule)
│   └── ...
├── your_app/                  # Your application code
├── docker-compose.yml         # Optional: Docker integration
└── README.md                  # Your project documentation
```

## Installation in Parent Project

### Automated Installation

Create an installation script in your parent project:

```bash
#!/bin/bash
# install-all.sh

echo "Installing HURRICANE v6-gatewayd..."
cd hurricane
./install.sh
cd ..

echo "Installing other components..."
# Your other installation steps here
```

### Makefile Integration

Add HURRICANE targets to your parent Makefile:

```makefile
# Parent project Makefile

.PHONY: install-hurricane start-hurricane stop-hurricane

install-hurricane:
	@echo "Installing HURRICANE v6-gatewayd..."
	cd hurricane && ./install.sh

start-hurricane:
	@echo "Starting HURRICANE services..."
	cd hurricane && ./hurricane start

stop-hurricane:
	@echo "Stopping HURRICANE services..."
	cd hurricane && ./hurricane stop

status-hurricane:
	@echo "HURRICANE service status:"
	cd hurricane && ./hurricane status

# Combined targets
install-all: install-hurricane
	@echo "Installing other components..."
	# Your installation steps

start-all: start-hurricane
	@echo "Starting other services..."
	# Your startup commands

stop-all: stop-hurricane
	@echo "Stopping other services..."
	# Your shutdown commands
```

## Docker Integration

### Dockerfile

```dockerfile
FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential git curl python3 python3-pip \
    iproute2 iptables net-tools \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Copy HURRICANE submodule
COPY hurricane/ /opt/hurricane/
WORKDIR /opt/hurricane

# Run installation
RUN ./install.sh

# Expose ports
EXPOSE 8642 8643

# Start services
CMD ["./hurricane", "start"]
```

### Docker Compose

```yaml
version: '3.8'

services:
  hurricane:
    build:
      context: .
      dockerfile: Dockerfile.hurricane
    container_name: hurricane-v6gatewayd
    privileged: true
    network_mode: host
    volumes:
      - ./hurricane/config:/opt/hurricane/config
      - ./hurricane/logs:/opt/hurricane/logs
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8642/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  your-app:
    build: .
    depends_on:
      - hurricane
    environment:
      - HURRICANE_API=http://hurricane:8643
```

## API Integration

### Python Integration

```python
# your_app/network_manager.py
import requests

class HurricaneClient:
    """Client for HURRICANE v6-gatewayd API"""

    def __init__(self, base_url='http://127.0.0.1:8643'):
        self.base_url = base_url

    def set_routing_mode(self, mode):
        """Set routing mode: ipv6, ipv9, or dual"""
        response = requests.post(
            f'{self.base_url}/routing/mode',
            json={'mode': mode}
        )
        return response.json()

    def add_split_tunnel_rule(self, name, pattern, route, priority=100):
        """Add a split tunneling rule"""
        response = requests.post(
            f'{self.base_url}/split-tunnel/rules',
            json={
                'name': name,
                'pattern': pattern,
                'route': route,
                'enabled': True,
                'priority': priority
            }
        )
        return response.json()

    def scan_target(self, target, ports='22,80,443', timeout=1.0):
        """Start a port scan"""
        response = requests.post(
            f'{self.base_url}/scanner/start',
            json={
                'target': target,
                'ports': ports,
                'timeout': timeout,
                'workers': 100
            }
        )
        return response.json()

    def get_health(self):
        """Get daemon health status"""
        response = requests.get(f'{self.base_url}/health')
        return response.json()

# Usage example
if __name__ == '__main__':
    client = HurricaneClient()

    # Set dual mode (IPv6 + IPv9)
    client.set_routing_mode('dual')

    # Add split tunnel rule for .chn domains
    client.add_split_tunnel_rule(
        name='China Sites',
        pattern='*.chn',
        route='ipv9'
    )

    # Scan a target
    result = client.scan_target('2001:470:1f1c:258::1')
    print(f"Scan started: {result['scan_id']}")
```

### Node.js Integration

```javascript
// your_app/hurricaneClient.js
const axios = require('axios');

class HurricaneClient {
    constructor(baseUrl = 'http://127.0.0.1:8643') {
        this.baseUrl = baseUrl;
    }

    async setRoutingMode(mode) {
        const response = await axios.post(`${this.baseUrl}/routing/mode`, {
            mode: mode
        });
        return response.data;
    }

    async addSplitTunnelRule(name, pattern, route, priority = 100) {
        const response = await axios.post(`${this.baseUrl}/split-tunnel/rules`, {
            name: name,
            pattern: pattern,
            route: route,
            enabled: true,
            priority: priority
        });
        return response.data;
    }

    async scanTarget(target, ports = '22,80,443', timeout = 1.0) {
        const response = await axios.post(`${this.baseUrl}/scanner/start`, {
            target: target,
            ports: ports,
            timeout: timeout,
            workers: 100
        });
        return response.data;
    }

    async getHealth() {
        const response = await axios.get(`${this.baseUrl}/health`);
        return response.data;
    }
}

module.exports = HurricaneClient;

// Usage example
const client = new HurricaneClient();

client.setRoutingMode('dual')
    .then(() => console.log('Routing mode set to dual'))
    .catch(err => console.error(err));
```

## Programmatic Control

### Starting HURRICANE from Your Application

```python
# your_app/services.py
import subprocess
import time
import requests

def start_hurricane():
    """Start HURRICANE services"""
    subprocess.run(['./hurricane/hurricane', 'start'], check=True)

    # Wait for services to be ready
    for _ in range(30):  # 30 second timeout
        try:
            response = requests.get('http://127.0.0.1:8642/health')
            if response.status_code == 200:
                print("HURRICANE services ready")
                return True
        except requests.ConnectionError:
            time.sleep(1)

    raise RuntimeError("HURRICANE services failed to start")

def stop_hurricane():
    """Stop HURRICANE services"""
    subprocess.run(['./hurricane/hurricane', 'stop'], check=True)

def get_hurricane_status():
    """Check if HURRICANE is running"""
    result = subprocess.run(
        ['./hurricane/hurricane', 'status'],
        capture_output=True,
        text=True
    )
    return result.returncode == 0
```

### Process Manager Integration (systemd)

```ini
# /etc/systemd/system/yourproject.service
[Unit]
Description=Your Project with HURRICANE
After=network.target

[Service]
Type=forking
User=youruser
WorkingDirectory=/opt/yourproject
ExecStartPre=/opt/yourproject/hurricane/hurricane start
ExecStart=/opt/yourproject/start-your-app.sh
ExecStop=/opt/yourproject/hurricane/hurricane stop
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

## Environment Variables

HURRICANE can be configured via environment variables when used as a submodule:

```bash
# Set in parent project's .env file

# HURRICANE configuration
HURRICANE_CONFIG_DIR=/opt/yourproject/hurricane/config
HURRICANE_LOG_DIR=/opt/yourproject/logs/hurricane
HURRICANE_API_PORT=8643
HURRICANE_DAEMON_PORT=8642

# Routing preferences
HURRICANE_DEFAULT_MODE=dual  # ipv6, ipv9, or dual

# Export for child processes
export HURRICANE_CONFIG_DIR HURRICANE_LOG_DIR
```

## Configuration Management

### Sharing Configuration

Your parent project can manage HURRICANE configuration:

```bash
yourproject/
├── hurricane/              # HURRICANE submodule
├── configs/
│   └── hurricane/         # Your HURRICANE configs
│       ├── tunnels/
│       │   └── production.toml
│       └── credentials/
│           └── production.creds
└── deploy.sh
```

Deployment script:

```bash
#!/bin/bash
# deploy.sh

# Copy configurations to HURRICANE
cp -r configs/hurricane/* hurricane/config/

# Start HURRICANE
cd hurricane
./hurricane start
cd ..

# Start your application
./start-app.sh
```

## Monitoring Integration

### Prometheus Metrics

HURRICANE exposes Prometheus metrics at `http://127.0.0.1:8642/metrics`

Add to your Prometheus configuration:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'hurricane-v6gatewayd'
    static_configs:
      - targets: ['localhost:8642']
    metrics_path: '/metrics'
    scrape_interval: 15s

  - job_name: 'your-application'
    static_configs:
      - targets: ['localhost:9090']
```

### Health Checks

```python
# your_app/health.py
import requests

def check_hurricane_health():
    """Health check for HURRICANE"""
    try:
        response = requests.get('http://127.0.0.1:8642/health', timeout=5)
        data = response.json()
        return {
            'status': data['status'],
            'v6_reachable': data.get('v6_reachable', False),
            'active_tunnels': data.get('active_tunnels', 0)
        }
    except Exception as e:
        return {'status': 'error', 'error': str(e)}
```

## Updating the Submodule

### Updating HURRICANE in Your Project

```bash
# Navigate to parent project
cd yourproject

# Update HURRICANE submodule to latest commit
cd hurricane
git pull origin main
cd ..

# Or update to specific version
cd hurricane
git checkout v1.2.0
cd ..

# Update submodule reference in parent
git add hurricane
git commit -m "Update HURRICANE to v1.2.0"
```

### Automated Updates

```bash
#!/bin/bash
# update-hurricane.sh

cd hurricane

# Fetch latest
git fetch origin

# Check if updates available
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main)

if [ "$LOCAL" != "$REMOTE" ]; then
    echo "Updates available for HURRICANE"

    # Stop services
    ./hurricane stop

    # Update
    git pull origin main

    # Reinstall if needed
    ./install.sh

    # Restart services
    ./hurricane start

    echo "HURRICANE updated successfully"
else
    echo "HURRICANE is up to date"
fi
```

## Troubleshooting

### Submodule Not Initialized

```bash
# If hurricane directory is empty
git submodule update --init --recursive
```

### Port Conflicts

If your application uses ports 8642 or 8643:

```python
# Start HURRICANE on different ports
import subprocess
import os

os.environ['HURRICANE_API_PORT'] = '9643'
os.environ['HURRICANE_DAEMON_PORT'] = '9642'

subprocess.run(['./hurricane/hurricane', 'start'])
```

### Permission Issues

```bash
# Grant execute permissions
chmod +x hurricane/hurricane
chmod +x hurricane/install.sh
chmod +x hurricane/scripts/*.py
```

## Best Practices

1. **Pin to Specific Versions**: Use tagged releases instead of tracking main
   ```bash
   cd hurricane && git checkout v1.0.0
   ```

2. **Isolate Configuration**: Keep your HURRICANE configs separate from the submodule
   ```bash
   yourproject/configs/hurricane/  # Your configs
   yourproject/hurricane/config/   # Symlink or copy target
   ```

3. **Health Checks**: Always verify HURRICANE is running before using its features
   ```python
   assert check_hurricane_health()['status'] == 'ok'
   ```

4. **Graceful Shutdown**: Stop HURRICANE before stopping your application
   ```bash
   trap './hurricane/hurricane stop' EXIT
   ```

5. **Log Management**: Route HURRICANE logs to your logging system
   ```bash
   tail -f hurricane/logs/*.log | your-log-aggregator
   ```

## Example Projects

### Full Stack Application

```
myapp/
├── hurricane/                 # HURRICANE submodule
├── backend/
│   └── server.py             # Uses HURRICANE API
├── frontend/
│   └── dashboard.jsx         # Proxies to HURRICANE WebUI
├── docker-compose.yml        # Orchestrates all services
├── Makefile                  # Unified commands
└── README.md
```

### Microservices Architecture

```
infrastructure/
├── hurricane/                 # IPv6/IPv9 gateway
├── api-gateway/              # Uses HURRICANE for routing
├── auth-service/
├── data-service/
└── monitoring/               # Scrapes HURRICANE metrics
```

## Support

For issues specific to HURRICANE integration:
- Check HURRICANE logs: `hurricane/logs/`
- Run diagnostics: `./hurricane/hurricane status`
- Review QUICKSTART.md for basic troubleshooting

For submodule-related issues:
- Git submodules documentation: https://git-scm.com/book/en/v2/Git-Tools-Submodules
- Ensure `git submodule update --init --recursive` was run

## License

When using HURRICANE as a submodule, ensure compliance with its license terms and include appropriate attribution in your project documentation.
