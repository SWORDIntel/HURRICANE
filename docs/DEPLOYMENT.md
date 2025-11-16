# HURRICANE v6-gatewayd Production Deployment Guide

This guide covers production deployment options, including Docker, systemd, and monitoring setup.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Deployment Methods](#deployment-methods)
  - [Native Installation](#native-installation)
  - [Docker Deployment](#docker-deployment)
  - [Docker Compose with Monitoring](#docker-compose-with-monitoring)
- [Security Hardening](#security-hardening)
- [Monitoring & Observability](#monitoring--observability)
- [Performance Tuning](#performance-tuning)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

- **OS**: Linux (kernel 4.9+ recommended for WireGuard)
- **CPU**: 1 core minimum, 2+ recommended
- **RAM**: 256MB minimum, 512MB recommended
- **Network**: IPv4 connectivity required
- **Privileges**: Root or CAP_NET_ADMIN capability

### Required Packages

```bash
# Debian/Ubuntu
sudo apt-get install -y \
    gcc make libssl-dev \
    libcurl4-openssl-dev \
    iproute2 iputils-ping \
    wireguard-tools curl

# RHEL/CentOS
sudo yum install -y \
    gcc make openssl-devel \
    libcurl-devel \
    iproute iputils \
    wireguard-tools curl
```

**Note:** `libcurl4-openssl-dev` (Debian/Ubuntu) or `libcurl-devel` (RHEL/CentOS) is required for the `he-update` utility. If not installed, the daemon will still build normally, but the auto-update client will be skipped.

---

## Deployment Methods

### Native Installation

#### 1. Build from Source

```bash
git clone https://github.com/SWORDIntel/HURRICANE.git
cd HURRICANE
make
sudo make install
```

#### 2. Configure

```bash
sudo cp config/v6-gatewayd.conf.example /etc/v6-gatewayd.conf
sudo nano /etc/v6-gatewayd.conf
```

Edit the configuration with your tunnel credentials.

#### 3. Install Systemd Service

```bash
sudo cp systemd/v6-gatewayd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable v6-gatewayd
sudo systemctl start v6-gatewayd
```

#### 4. Verify Installation

```bash
# Check service status
sudo systemctl status v6-gatewayd

# Test API
curl http://localhost:8642/health

# View logs
sudo journalctl -u v6-gatewayd -f
```

---

### Docker Deployment

#### 1. Build Docker Image

```bash
docker build -t hurricane/v6-gatewayd:latest .
```

#### 2. Run Container

```bash
docker run -d \
  --name v6-gatewayd \
  --network host \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  -v /etc/v6-gatewayd.conf:/etc/v6-gatewayd.conf:ro \
  -v /etc/wireguard:/etc/wireguard:ro \
  -v v6gw-data:/var/lib/v6-gatewayd \
  --restart unless-stopped \
  hurricane/v6-gatewayd:latest
```

#### 3. Check Container Health

```bash
docker ps | grep v6-gatewayd
docker logs v6-gatewayd
docker exec v6-gatewayd curl http://localhost:8642/health
```

---

### Docker Compose with Monitoring

#### 1. Start Full Stack

```bash
# Start daemon only
docker-compose up -d

# Start with Prometheus and Grafana
docker-compose --profile monitoring up -d
```

#### 2. Access Services

- **API**: http://localhost:8642
- **WebUI**: http://localhost:8642/ui
- **Prometheus**: http://localhost:9090
- **Grafana**: http://localhost:3000 (admin/admin)

#### 3. Configure Grafana Dashboard

1. Login to Grafana (http://localhost:3000)
2. Add Prometheus data source: http://prometheus:9090
3. Import dashboard or create custom panels with metrics:
   - `v6gw_tunnel_state`
   - `v6gw_tunnel_health_score`
   - `v6gw_tunnel_latency_ms`
   - `v6gw_tunnel_tx_bytes`
   - `v6gw_tunnel_rx_bytes`

---

## Security Hardening

### Systemd Hardening

The provided systemd service includes comprehensive security hardening:

```ini
# Filesystem isolation
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

# Device access control
PrivateDevices=false
DevicePolicy=closed
DeviceAllow=/dev/net/tun rw

# Network restrictions
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK

# Capability restrictions
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE

# System call filtering
SystemCallFilter=@system-service @network-io

# Resource limits
MemoryMax=512M
CPUQuota=200%
```

### Firewall Configuration

Allow API access only from localhost:

```bash
# UFW
sudo ufw allow from 127.0.0.1 to any port 8642
sudo ufw deny 8642

# iptables
sudo iptables -A INPUT -s 127.0.0.1 -p tcp --dport 8642 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8642 -j DROP
```

### File Permissions

```bash
sudo chmod 600 /etc/v6-gatewayd.conf
sudo chown root:root /etc/v6-gatewayd.conf
```

---

## Monitoring & Observability

### Health Checks

```bash
# API health check
curl http://localhost:8642/health

# Systemd health
systemctl is-active v6-gatewayd

# Docker health
docker inspect --format='{{.State.Health.Status}}' v6-gatewayd
```

### Prometheus Metrics

The daemon exposes Prometheus metrics at `/metrics`:

```bash
curl http://localhost:8642/metrics
```

**Key Metrics:**
- `v6gw_tunnel_state` - Tunnel state (0=down, 1=up, 2=error)
- `v6gw_tunnel_health_score` - Health score (0-100)
- `v6gw_tunnel_latency_ms` - Latency in milliseconds
- `v6gw_tunnel_tx_bytes` - Bytes transmitted (counter)
- `v6gw_tunnel_rx_bytes` - Bytes received (counter)
- `v6gw_tunnel_reachable` - Reachability (0=no, 1=yes)

### Log Management

```bash
# Systemd logs
sudo journalctl -u v6-gatewayd -f

# Docker logs
docker logs -f v6-gatewayd

# Export logs via API
curl http://localhost:8642/logs?limit=1000 > logs.json
```

### WebUI Dashboard

Access the TEMPEST WebUI at http://localhost:8642/ui for:

- Real-time tunnel monitoring
- Bandwidth/latency/health graphs
- Configuration viewer
- Activity log viewer
- Tunnel control (start/stop/restart)

---

## Performance Tuning

### Resource Limits

Adjust systemd service limits based on your workload:

```ini
# /etc/systemd/system/v6-gatewayd.service
[Service]
LimitNOFILE=65536      # Max open files
LimitNPROC=512         # Max processes
TasksMax=256           # Max tasks
MemoryMax=512M         # Memory limit
CPUQuota=200%          # CPU limit (200% = 2 cores)
```

### Kernel Tuning

For high-throughput scenarios:

```bash
# Increase network buffers
sudo sysctl -w net.core.rmem_max=16777216
sudo sysctl -w net.core.wmem_max=16777216

# Optimize connection tracking
sudo sysctl -w net.netfilter.nf_conntrack_max=262144

# Make permanent
echo "net.core.rmem_max=16777216" | sudo tee -a /etc/sysctl.conf
echo "net.core.wmem_max=16777216" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### API Performance

Monitor API response times:

```bash
# Run benchmarks
./tests/benchmark.sh

# Expected results:
# - GET /health: <50ms average
# - GET /tunnels: <100ms average
# - Requests/sec: >100 req/s
```

---

## Troubleshooting

### Daemon Won't Start

**Check configuration:**
```bash
sudo /usr/local/bin/v6-gatewayd -c /etc/v6-gatewayd.conf -t
```

**Check logs:**
```bash
sudo journalctl -u v6-gatewayd -n 50
```

**Common issues:**
- Missing configuration file
- Invalid tunnel credentials
- Permission errors (requires root)
- Port 8642 already in use

### Tunnel Not Connecting

**Check tunnel status:**
```bash
curl http://localhost:8642/tunnels | jq
```

**Test IPv6 connectivity:**
```bash
ip -6 addr show
ping6 -c 3 2001:4860:4860::8888
```

**For WireGuard:**
```bash
sudo wg show
sudo wg-quick up mullvad0
```

### API Not Responding

**Check if daemon is running:**
```bash
systemctl status v6-gatewayd
ps aux | grep v6-gatewayd
```

**Test API locally:**
```bash
curl -v http://127.0.0.1:8642/health
```

**Check firewall:**
```bash
sudo iptables -L -n | grep 8642
sudo ufw status | grep 8642
```

### Docker Container Issues

**Check container logs:**
```bash
docker logs v6-gatewayd --tail 100
```

**Exec into container:**
```bash
docker exec -it v6-gatewayd /bin/bash
```

**Restart container:**
```bash
docker-compose restart v6-gatewayd
```

### Performance Issues

**Check resource usage:**
```bash
# CPU and memory
top -p $(pgrep v6-gatewayd)

# Network
sudo iftop -i he0

# Disk I/O
sudo iotop -p $(pgrep v6-gatewayd)
```

**Run benchmarks:**
```bash
./tests/benchmark.sh
```

**Check tunnel health:**
```bash
curl http://localhost:8642/tunnels | jq '.tunnels[].health_score'
```

---

## Backup & Recovery

### Configuration Backup

```bash
# Backup config
sudo cp /etc/v6-gatewayd.conf /etc/v6-gatewayd.conf.backup

# Export via API
curl http://localhost:8642/config > config-backup.json
```

### State Directory Backup

```bash
sudo tar czf v6gw-backup-$(date +%Y%m%d).tar.gz \
    /var/lib/v6-gatewayd \
    /etc/v6-gatewayd.conf \
    /etc/wireguard
```

### Restore Procedure

```bash
# Stop daemon
sudo systemctl stop v6-gatewayd

# Restore config
sudo tar xzf v6gw-backup-YYYYMMDD.tar.gz -C /

# Start daemon
sudo systemctl start v6-gatewayd
```

---

## Production Checklist

- [ ] Configuration file secured (chmod 600)
- [ ] Systemd service enabled
- [ ] Firewall configured (API localhost-only)
- [ ] Health checks configured
- [ ] Monitoring enabled (Prometheus/Grafana)
- [ ] Logs rotation configured
- [ ] Backup procedure established
- [ ] Resource limits tuned
- [ ] Security hardening applied
- [ ] Documentation updated

---

## Support

- **GitHub**: https://github.com/SWORDIntel/HURRICANE
- **Issues**: https://github.com/SWORDIntel/HURRICANE/issues
- **Documentation**: https://github.com/SWORDIntel/HURRICANE/tree/main/docs
