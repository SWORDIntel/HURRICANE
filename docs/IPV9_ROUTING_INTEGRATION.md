# IPv9 Routing Integration Guide

**HURRICANE v6-gatewayd + IPVNINER Integration**

This document describes the IPv9/IPv6 dual routing integration added to HURRICANE.

---

## Overview

IPVNINER has been integrated as a git submodule to provide optional IPv9 (China Decimal Network) routing alongside standard IPv6 Hurricane Electric tunnels.

**Key Features:**
- Switch between IPv6, IPv9, or Dual routing modes
- Simultaneous routing to both networks when in Dual mode
- Web UI controls for mode switching
- API endpoints for programmatic control
- DNS resolution through IPv9 servers for .chn domains

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                HURRICANE v6-gatewayd                        │
│                                                             │
│  ┌──────────────────┐        ┌──────────────────┐          │
│  │  IPv6 Tunnels    │        │  IPv9 DNS Layer  │          │
│  │  (HE 6in4)       │        │  (IPVNINER)      │          │
│  │                  │        │                  │          │
│  │  2001:470::/64   │        │  .chn domains    │          │
│  │  HE Tunnel       │        │  202.170.218.93  │          │
│  └──────────────────┘        └──────────────────┘          │
│           │                           │                     │
│           └───────────┬───────────────┘                     │
│                       │                                     │
│              ┌────────▼────────┐                            │
│              │  Routing Layer  │                            │
│              │  (Mode: DUAL)   │                            │
│              └────────┬────────┘                            │
│                       │                                     │
│              ┌────────▼────────┐                            │
│              │   API + WebUI   │                            │
│              │   Port 8643     │                            │
│              └─────────────────┘                            │
└─────────────────────────────────────────────────────────────┘
```

---

## Installation

### 1. Submodule Already Added

IPVNINER is already integrated as a git submodule:

```bash
# Check submodule status
git submodule status

# Should show:
# <commit-hash> ipvniner (heads/main)
```

### 2. Install Python Dependencies

```bash
# Install Flask for router API
pip3 install flask requests

# Install IPVNINER dependencies (optional, for full IPv9 support)
cd ipvniner && pip3 install -r requirements.txt && cd ..
```

### 3. Launch Router API Service

The router API runs alongside v6-gatewayd on port 8643:

```bash
# Start manually
python3 scripts/router-api-standalone.py

# Or add to systemd (see below)
```

---

## Routing Modes

### IPv6 Mode (Default)

Standard IPv6 routing through Hurricane Electric tunnel:

```bash
# Set IPv6 mode
curl -X POST http://localhost:8643/routing/mode \
  -H "Content-Type: application/json" \
  -d '{"mode": "ipv6"}'
```

- IPv6 enabled: ✓
- IPv9 enabled: ✗
- Best for: Standard IPv6 internet access

### IPv9 Mode

IPv9 DNS overlay routing for .chn domains:

```bash
# Set IPv9 mode
curl -X POST http://localhost:8643/routing/mode \
  -H "Content-Type: application/json" \
  -d '{"mode": "ipv9"}'
```

- IPv6 enabled: ✗
- IPv9 enabled: ✓
- DNS Servers: 202.170.218.93, 61.244.5.162
- Best for: China Decimal Network exploration

### Dual Mode (Recommended)

Both IPv6 and IPv9 routing active simultaneously:

```bash
# Set Dual mode
curl -X POST http://localhost:8643/routing/mode \
  -H "Content-Type: application/json" \
  -d '{"mode": "dual"}'
```

- IPv6 enabled: ✓
- IPv9 enabled: ✓
- Best for: Maximum flexibility, research, testing

**Dual Mode Behavior:**
- `.chn` domains → IPv9 DNS resolution
- Standard domains → IPv6/IPv4 resolution
- Both networks accessible simultaneously
- Prefer IPv9 for .chn TLD

---

## API Endpoints

The Router API adds these endpoints (port 8643):

### GET /routing/status

Get current routing configuration:

```bash
curl http://localhost:8643/routing/status
```

Response:
```json
{
  "routing_mode": "dual",
  "ipv6_enabled": true,
  "ipv9_enabled": true,
  "prefer_ipv9": false,
  "ipv9_available": true,
  "ipv9_dns_servers": ["202.170.218.93", "61.244.5.162"]
}
```

### GET/POST /routing/mode

Get or set routing mode:

```bash
# Get current mode
curl http://localhost:8643/routing/mode

# Set mode
curl -X POST http://localhost:8643/routing/mode \
  -H "Content-Type: application/json" \
  -d '{"mode": "dual"}'
```

### Proxy to v6-gatewayd

All other endpoints proxy to v6-gatewayd (port 8642):

```bash
# These work through port 8643 (router API)
curl http://localhost:8643/health
curl http://localhost:8643/tunnels
curl http://localhost:8643/v6/address
```

---

## Web UI Integration

### Adding Routing Panel to WebUI

Insert this HTML after the "IPv6 Addresses Panel" in `/usr/local/share/v6-gatewayd/web/index.html`:

```html
<!-- Routing Mode Panel -->
<div class="panel">
    <div class="panel-header">
        <span>⬢ ROUTING MODE</span>
        <span id="routing-mode-display" style="font-size: 10px; color: var(--text-dim);">IPv6</span>
    </div>
    <div class="panel-body">
        <div class="metric">
            <span class="metric-label">CURRENT MODE</span>
            <span class="metric-value" id="current-routing-mode">IPv6</span>
        </div>
        <div class="metric">
            <span class="metric-label">IPv6 ENABLED</span>
            <span class="metric-value" id="ipv6-enabled">✓</span>
        </div>
        <div class="metric">
            <span class="metric-label">IPv9 ENABLED</span>
            <span class="metric-value" id="ipv9-enabled">✗</span>
        </div>
        <div style="margin-top: 15px; display: flex; gap: 10px;">
            <button onclick="setRoutingMode('ipv6')" style="flex: 1; padding: 8px; background: var(--secondary-bg); border: 1px solid var(--border-color); color: var(--text-primary); cursor: pointer; text-transform: uppercase;">IPv6</button>
            <button onclick="setRoutingMode('ipv9')" style="flex: 1; padding: 8px; background: var(--secondary-bg); border: 1px solid var(--border-color); color: var(--text-primary); cursor: pointer; text-transform: uppercase;">IPv9</button>
            <button onclick="setRoutingMode('dual')" style="flex: 1; padding: 8px; background: var(--secondary-bg); border: 1px solid var(--border-color); color: var(--text-primary); cursor: pointer; text-transform: uppercase;">DUAL</button>
        </div>
    </div>
</div>
```

### JavaScript Functions

Add these functions to the `<script>` section:

```javascript
// Fetch routing status
async function fetchRoutingStatus() {
    try {
        const response = await fetch(`${API_BASE}/routing/status`);
        const data = await response.json();

        document.getElementById('current-routing-mode').textContent = data.routing_mode.toUpperCase();
        document.getElementById('routing-mode-display').textContent = data.routing_mode.toUpperCase();
        document.getElementById('ipv6-enabled').textContent = data.ipv6_enabled ? '✓' : '✗';
        document.getElementById('ipv9-enabled').textContent = data.ipv9_enabled ? '✓' : '✗';

        // Color code the mode
        const modeElement = document.getElementById('current-routing-mode');
        if (data.routing_mode === 'dual') {
            modeElement.style.color = '#00aaff';
        } else if (data.routing_mode === 'ipv9') {
            modeElement.style.color = '#ffaa00';
        } else {
            modeElement.style.color = '#00ff00';
        }
    } catch (error) {
        console.error('Failed to fetch routing status:', error);
    }
}

// Set routing mode
async function setRoutingMode(mode) {
    try {
        const response = await fetch(`${API_BASE}/routing/mode`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({mode: mode})
        });

        if (response.ok) {
            showSuccess(`Routing mode set to ${mode.toUpperCase()}`);
            addLog('INFO', `Routing mode changed to ${mode.toUpperCase()}`);
            setTimeout(fetchRoutingStatus, 500);
        } else {
            showError(`Failed to set routing mode to ${mode}`);
        }
    } catch (error) {
        showError(`Routing mode change failed: ${error.message}`);
    }
}

// Update updateDashboard() to include routing status
async function updateDashboard() {
    // ... existing code ...
    await Promise.all([
        fetchHealth(),
        fetchAddresses(),
        fetchTunnels(),
        fetchRoutingStatus()  // ADD THIS LINE
    ]);
}
```

### Update API Base URL

Change the API base URL to use the router API (port 8643):

```javascript
const API_BASE = 'http://localhost:8643';  // Changed from 8642
```

---

## Systemd Service

Create `/etc/systemd/system/hurricane-router-api.service`:

```ini
[Unit]
Description=Hurricane Router API - IPv9/IPv6 Routing Layer
Documentation=https://github.com/SWORDIntel/HURRICANE
After=v6-gatewayd.service
Requires=v6-gatewayd.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/share/v6-gatewayd/scripts/router-api-standalone.py
Restart=on-failure
RestartSec=5s

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc

# Resource limits
MemoryMax=128M
CPUQuota=50%

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=hurricane-router-api

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable hurricane-router-api
sudo systemctl start hurricane-router-api
sudo systemctl status hurricane-router-api
```

---

## Configuration File

The routing configuration is stored in `/etc/v6-gatewayd-routing.conf`:

```json
{
  "mode": "dual",
  "ipv9_dns_servers": [
    "202.170.218.93",
    "61.244.5.162"
  ],
  "ipv9_enabled": true,
  "ipv6_enabled": true,
  "prefer_ipv9": false
}
```

---

## CLI Usage

### Check Routing Status

```bash
python3 scripts/hurricane-router.py status
```

### Set Routing Mode

```bash
# Set to IPv6 mode
python3 scripts/hurricane-router.py set-mode ipv6

# Set to IPv9 mode
python3 scripts/hurricane-router.py set-mode ipv9

# Set to Dual mode
python3 scripts/hurricane-router.py set-mode dual
```

### Resolve Domain

```bash
# Resolve .chn domain (uses IPv9 in dual mode)
python3 scripts/hurricane-router.py resolve www.v9.chn

# Resolve standard domain (uses IPv6/IPv4)
python3 scripts/hurricane-router.py resolve ipv6.google.com
```

### Test Connectivity

```bash
python3 scripts/hurricane-router.py test
```

---

## IPv9 Network Details

### What is IPv9?

IPv9 is China's experimental "decimal network" that uses:
- **Numeric domain names** based on phone numbers (e.g., `8613812345678.chn`)
- **Special DNS servers** at 202.170.218.93 and 61.244.5.162
- **Standard IP routing** - domains resolve to normal IPv4/IPv6 addresses
- **DNS overlay architecture** - no new protocol required

### Example IPv9 Sites

- `www.v9.chn` - IPv9 portal
- `em777.chn` - Media site
- `www.hqq.chn` - Service site

### DNS Resolution Process

1. Client queries `.chn` domain
2. Request sent to IPv9 DNS servers
3. IPv9 DNS returns IPv4 address
4. Standard IP routing used for connection

---

## Troubleshooting

### Router API Not Starting

```bash
# Check if v6-gatewayd is running
sudo systemctl status v6-gatewayd

# Check logs
sudo journalctl -u hurricane-router-api -n 50
```

### IPv9 Resolution Failing

```bash
# Test IPv9 DNS servers directly
dig @202.170.218.93 www.v9.chn

# Check if IPVNINER is installed
python3 -c "from ipv9tool.core.dns_resolver import DNSResolver; print('OK')"
```

### Dual Mode Not Working

```bash
# Check routing config
cat /etc/v6-gatewayd-routing.conf

# Verify both protocols enabled
curl http://localhost:8643/routing/status | jq
```

---

## Security Considerations

1. **IPv9 DNS Servers**: Hosted in China, may log queries
2. **Dual Mode**: Both networks accessible - ensure firewall rules are appropriate
3. **DNS Leakage**: .chn queries go to IPv9 servers even in dual mode
4. **Experimental Network**: IPv9 is not widely deployed or standardized

---

## Future Enhancements

- [ ] IPv9 tunnel support (if protocol spec becomes available)
- [ ] DNS-over-HTTPS for IPv9 queries
- [ ] Routing policy rules (domain-based routing)
- [ ] Performance metrics for both networks
- [ ] Automatic failover between IPv6/IPv9

---

## References

- **IPVNINER**: https://github.com/SWORDIntel/IPVNINER
- **Hurricane Electric**: https://tunnelbroker.net
- **IPv9 Information**: Research papers on China's decimal network

---

## Support

- HURRICANE Issues: https://github.com/SWORDIntel/HURRICANE/issues
- IPVNINER Issues: https://github.com/SWORDIntel/IPVNINER/issues

---

**Integrated IPv9/IPv6 Routing - HURRICANE v6-gatewayd** 🚀
