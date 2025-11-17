# FASTPORT IPv6 Integration

**High-Performance IPv6 Port Scanner for Hurricane Electric Tunnels**

FASTPORT IPv6 extends the blazing-fast FASTPORT scanner with native IPv6 support, seamlessly integrated with the HURRICANE v6-gatewayd tunnel system.

---

## 🌐 Overview

This integration allows you to:
- **Scan IPv6 hosts** through Hurricane Electric 6in4 tunnels
- **Leverage FASTPORT's speed** (20-25M packets/sec) for IPv6 targets
- **Auto-detect IPv6 connectivity** via v6-gatewayd API
- **CVE vulnerability scanning** on IPv6 services
- **Native IPv6 socket operations** with automatic source address selection

---

## 🚀 Quick Start

### Prerequisites

1. **HURRICANE v6-gatewayd running** with active tunnel:
   ```bash
   sudo systemctl status v6-gatewayd
   ```

2. **IPv6 connectivity verified**:
   ```bash
   curl http://localhost:8642/health
   ```

### Installation

FASTPORT IPv6 is pre-integrated - no installation needed!

```bash
# Check IPv6 connectivity
./fastport-ipv6 --check

# Scan an IPv6 host (common ports)
./fastport-ipv6 2001:470:1f1c:258::1

# Scan specific ports
./fastport-ipv6 2001:470:1f1c:258::1 -p 22,80,443,3389

# Scan port range with CVE lookup
./fastport-ipv6 2001:470:1f1c:258::1 -r 1-1000 --cve -v

# Save results to JSON
./fastport-ipv6 2001:470:1f1c:258::1 -o scan-results.json
```

---

## 📋 Features

### Core Capabilities

✅ **Native IPv6 Support**
- IPv6 socket operations (AF_INET6)
- Automatic IPv6 address resolution
- Hurricane Electric tunnel integration
- Source IPv6 address selection

✅ **v6-gatewayd Integration**
- Automatic tunnel health checking
- IPv6 address discovery via API
- Real-time tunnel status monitoring
- Graceful fallback on connectivity issues

✅ **All FASTPORT Features**
- AVX-512/AVX2 SIMD acceleration (Python async backend)
- Concurrent scanning with configurable workers
- Banner grabbing and service detection
- CVE vulnerability lookup (NVD database)
- JSON export for automation

✅ **IPv6-Specific Enhancements**
- Link-local vs global address preference
- IPv6 hostname resolution
- Dual-stack detection
- IPv6 CIDR range support (planned)

---

## 🔧 Usage

### Basic Scanning

```bash
# Scan IPv6 host on common ports
./fastport-ipv6 2001:470:1f1c:258::1

# Scan with verbose output
./fastport-ipv6 2001:470:1f1c:258::1 -v

# Custom timeout (useful for slow networks)
./fastport-ipv6 2001:470:1f1c:258::1 -t 2.0
```

### Port Selection

```bash
# Specific ports
./fastport-ipv6 2001:db8::1 -p 22,80,443,8080

# Port range
./fastport-ipv6 2001:db8::1 -r 1-1024

# All common ports (default: 22, 80, 443, 8080, 8443, 3389, 3306, 5432, 6379, 27017)
./fastport-ipv6 2001:db8::1
```

### CVE Vulnerability Scanning

```bash
# Enable CVE lookup for detected services
./fastport-ipv6 2001:470:1f1c:258::1 --cve

# CVE scan with verbose output
./fastport-ipv6 2001:470:1f1c:258::1 --cve -v

# Save CVE results to JSON
./fastport-ipv6 2001:470:1f1c:258::1 --cve -o vuln-report.json
```

### Advanced Options

```bash
# Custom v6-gatewayd API URL
./fastport-ipv6 2001:db8::1 --api http://192.168.1.100:8642

# More concurrent workers for faster scans
./fastport-ipv6 2001:db8::1 -w 500 -r 1-65535

# Check connectivity only (no scan)
./fastport-ipv6 --check
```

---

## 📊 Example Output

```
$ ./fastport-ipv6 2001:470:1f1c:258::1 -p 22,80,443 --cve -v

[IPv6Scanner] v6-gatewayd health: ok
[IPv6Scanner] Found 1 active tunnel(s)
[IPv6Scanner]   - he0: 2001:470:1f1c:258::2 (health: 100)
[IPv6Scanner] Using source IPv6: 2001:470:1f1c:258::2
[IPv6Scanner] Scanning 2001:470:1f1c:258::1 on 3 ports...
[IPv6Scanner] Found 2 open ports: [22, 443]
[IPv6Scanner] Performing CVE lookup...

============================================================
Scan Results for 2001:470:1f1c:258::1
============================================================
Total ports scanned: 3
Open ports found: 2
============================================================

PORT       STATE      SERVICE              BANNER
----------------------------------------------------------------------
22         open       SSH                  SSH-2.0-OpenSSH_8.9p1
443        open       HTTPS                -

============================================================
CVE Vulnerabilities Found
============================================================

Port 22:
  - CVE-2023-38408: OpenSSH vulnerability allowing remote code exec
  - CVE-2023-51385: OpenSSH X11 forwarding bypass

Results saved to: scan-results.json
```

---

## 🔌 Integration with v6-gatewayd

### API Endpoints Used

FASTPORT IPv6 integrates with these v6-gatewayd API endpoints:

1. **Health Check** (`GET /health`)
   - Verifies daemon is running
   - Checks overall system health

2. **Tunnel Status** (`GET /tunnels`)
   - Lists all configured tunnels
   - Filters for active (state='up') tunnels
   - Retrieves IPv6 addresses and health scores

3. **IPv6 Addresses** (`GET /v6/address`)
   - Gets all available IPv6 addresses
   - Checks reachability status
   - Prefers global addresses over link-local

### Automatic Source Selection

The scanner automatically selects the best source IPv6 address:

1. Queries v6-gatewayd for available IPv6 addresses
2. Filters out link-local addresses (fe80::)
3. Selects first reachable global IPv6 address
4. Falls back to link-local if no global addresses available

---

## 🛠️ Python API

You can also use FASTPORT IPv6 programmatically:

```python
import asyncio
from fastport.scanner_ipv6 import IPv6Scanner

async def scan_example():
    # Create scanner
    scanner = IPv6Scanner(api_url="http://localhost:8642", verbose=True)

    # Check connectivity
    if scanner.check_ipv6_connectivity():
        print("IPv6 connectivity OK")

    # Get source address
    source = scanner.get_source_ipv6()
    print(f"Source IPv6: {source}")

    # Scan target
    results = await scanner.scan_async(
        target="2001:470:1f1c:258::1",
        ports=[22, 80, 443, 8080],
        timeout=1.0,
        workers=100,
        enable_cve=True
    )

    # Process results
    print(f"Found {results['open_ports']} open ports")
    for port_info in results['results']:
        print(f"  {port_info['port']}: {port_info['service']}")

    # CVE results
    if results.get('cves'):
        for port, cves in results['cves'].items():
            print(f"Port {port} has {len(cves)} CVEs")

# Run
asyncio.run(scan_example())
```

---

## 🎯 Use Cases

### 1. IPv6 Network Reconnaissance

Scan your Hurricane Electric routed /64 prefix:

```bash
# Scan entire /64 (requires iteration script - TODO)
for i in {1..10}; do
    ./fastport-ipv6 2001:470:1f1c:258::$i -p 22,80,443
done
```

### 2. Vulnerability Assessment

Identify CVEs on IPv6-exposed services:

```bash
# Full vulnerability scan on critical infrastructure
./fastport-ipv6 2001:470:1f1c:258::100 \
    -r 1-65535 \
    --cve \
    -o critical-host-vuln-scan.json
```

### 3. Service Discovery

Find what's running on IPv6:

```bash
# Quick service discovery
./fastport-ipv6 2001:470:1f1c:258::1 -v | grep open
```

### 4. Continuous Monitoring

Integrate with cron for periodic scanning:

```bash
# /etc/cron.daily/ipv6-scan
#!/bin/bash
/path/to/fastport-ipv6 2001:470:1f1c:258::1 \
    --cve \
    -o /var/log/ipv6-scans/scan-$(date +%Y%m%d).json
```

---

## ⚙️ Configuration

### Default Settings

```python
# API URL
api_url = "http://localhost:8642"

# Socket timeout
timeout = 1.0

# Concurrent workers
workers = 100

# Default ports (if none specified)
default_ports = [22, 80, 443, 8080, 8443, 3389, 3306, 5432, 6379, 27017]
```

### Environment Variables

```bash
# Set custom API URL
export V6GW_API_URL="http://192.168.1.100:8642"
./fastport-ipv6 2001:db8::1
```

---

## 🐛 Troubleshooting

### "v6-gatewayd daemon not responding"

**Solution:**
```bash
# Check if daemon is running
sudo systemctl status v6-gatewayd

# Start if stopped
sudo systemctl start v6-gatewayd

# Check API is accessible
curl http://localhost:8642/health
```

### "No active IPv6 tunnels available"

**Solution:**
```bash
# Check tunnel status
curl http://localhost:8642/tunnels | jq .

# Restart tunnel
sudo systemctl restart v6-gatewayd

# Manual tunnel check
ip -6 addr show
ping6 -c 3 2001:4860:4860::8888
```

### "Failed to resolve target to IPv6"

**Solution:**
```bash
# Verify target is valid IPv6
ping6 -c 3 2001:470:1f1c:258::1

# Check DNS resolution
host -t AAAA ipv6.google.com

# Try direct IPv6 address instead of hostname
./fastport-ipv6 2001:4860:4860::8888 -p 53
```

### Slow Scan Performance

**Solution:**
```bash
# Reduce timeout
./fastport-ipv6 TARGET -t 0.5

# Increase workers
./fastport-ipv6 TARGET -w 500

# Scan smaller port ranges
./fastport-ipv6 TARGET -r 1-1024
```

---

## 📚 Technical Details

### IPv6 Socket Operations

```python
# Create IPv6 socket
sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
sock.settimeout(timeout)

# Connect to IPv6 host
sock.connect((target_ipv6, port))
```

### Banner Grabbing

```python
# Receive banner after connection
banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
```

### CVE Lookup

Integrates with existing FASTPORT CVE scanner:
- Queries NVD database via API
- Filters by service version
- Highlights RCE vulnerabilities
- CVSS severity scoring

---

## 🔜 Future Enhancements

- [ ] IPv6 CIDR range scanning (2001:db8::/64)
- [ ] Parallel scanning of multiple targets
- [ ] Integration with original FASTPORT Rust core for IPv6
- [ ] TUI interface for IPv6 scans
- [ ] IPv6 traceroute integration
- [ ] Firewall detection (IPv6 filtering)
- [ ] ICMPv6 probe support

---

## 🤝 Credits

- **FASTPORT**: Original high-performance scanner with AVX-512 SIMD
- **HURRICANE v6-gatewayd**: IPv6 tunnel management system
- **Hurricane Electric**: Free IPv6 tunnel broker (tunnelbroker.net)

---

## 📄 License

Same license as FASTPORT (MIT) and HURRICANE (MIT)

---

## 🆘 Support

- FASTPORT Issues: https://github.com/SWORDIntel/FASTPORT/issues
- HURRICANE Issues: https://github.com/SWORDIntel/HURRICANE/issues
- Hurricane Electric Forum: https://forums.he.net/

---

**Happy IPv6 Scanning! 🚀**
