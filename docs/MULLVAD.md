# Mullvad VPN Integration

HURRICANE v6-gatewayd supports Mullvad VPN through the WireGuard backend, providing a privacy-focused VPN tunnel with IPv4 connectivity and optional IPv6 support.

## Why Mullvad?

- **Privacy-Focused**: No logging, anonymous accounts, accepts cash/crypto
- **WireGuard Native**: Excellent WireGuard implementation
- **Dual-Stack Support**: IPv4 (required) + IPv6 (optional)
- **Multiple Locations**: 600+ servers in 40+ countries
- **High Performance**: Low latency, high bandwidth

## IPv4 vs IPv6

v6-gatewayd is designed for **IPv4-first** operation:
- **IPv4**: Primary connectivity mode (always works)
- **IPv6**: Optional enhancement (detected automatically)
- Mullvad provides both IPv4 and IPv6 addresses
- System functions normally with or without IPv6

## Prerequisites

1. **Mullvad Account**: Sign up at https://mullvad.net
   - Note your account number (16 digits)
   - No email or personal info required

2. **WireGuard Tools**: Install on your system
   ```bash
   # Debian/Ubuntu
   sudo apt install wireguard-tools

   # RHEL/Fedora
   sudo dnf install wireguard-tools

   # Arch
   sudo pacman -S wireguard-tools
   ```

3. **Root Access**: Required for WireGuard tunnel management

## Quick Start

### Step 1: Generate Mullvad WireGuard Config

1. Go to https://mullvad.net/en/account/#/wireguard-config
2. Log in with your account number
3. Generate a new WireGuard key
4. Select your preferred server location (choose one with low latency)
5. **Enable IPv6** (important!)
6. Download the configuration file (e.g., `mullvad-us-nyc-001.conf`)

### Step 2: Install Mullvad Config

```bash
# Copy Mullvad config to WireGuard directory
sudo cp mullvad-us-nyc-001.conf /etc/wireguard/mullvad0.conf

# Set correct permissions
sudo chmod 600 /etc/wireguard/mullvad0.conf

# Test the configuration
sudo wg-quick up mullvad0
sudo wg show
sudo wg-quick down mullvad0
```

### Step 3: Configure v6-gatewayd

Edit `/etc/v6-gatewayd.conf`:

**Option A: IPv4 + IPv6 (Recommended)**
```ini
[core]
log_level = "info"
state_dir = "/var/lib/v6-gatewayd"

[api]
bind = "127.0.0.1"
port = 8642

[exposure]
mode = "kernel"

[tunnel1]
name = "mullvad-nyc"
type = "wireguard"
iface = "mullvad0"
v6_prefix = "fc00:bbbb:bbbb:bb01::1"  # Optional: From Mullvad config if IPv6 enabled
enabled = true
priority = 0
```

**Option B: IPv4 Only (Still works!)**
```ini
[core]
log_level = "info"
state_dir = "/var/lib/v6-gatewayd"

[api]
bind = "127.0.0.1"
port = 8642

[exposure]
mode = "kernel"

[tunnel1]
name = "mullvad-nyc"
type = "wireguard"
iface = "mullvad0"
# v6_prefix is optional - omit if IPv6 not available
enabled = true
priority = 0
```

**Note**: v6-gatewayd works with IPv4-only tunnels. IPv6 support is detected automatically. If your Mullvad config only has IPv4, the daemon will still function normally for IPv4 connectivity.

### Step 4: Start v6-gatewayd

```bash
# Start the service
sudo systemctl start v6-gatewayd

# Check status
sudo systemctl status v6-gatewayd

# View logs
sudo journalctl -u v6-gatewayd -f
```

### Step 5: Verify IPv6 Connectivity

```bash
# Check tunnel is up
curl http://localhost:8642/tunnels

# Get IPv6 address
curl http://localhost:8642/v6/address

# Test IPv6 connectivity
ping6 -c 3 2001:4860:4860::8888

# Check your IPv6 address (should show Mullvad)
curl -6 https://am.i.mullvad.net/json
```

## Mullvad Config Format

A typical Mullvad WireGuard config looks like this:

```ini
[Interface]
PrivateKey = XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX=
Address = 10.68.X.X/32,fc00:bbbb:bbbb:bb01::X:XXXX/128
DNS = 10.64.0.1

[Peer]
PublicKey = YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY=
AllowedIPs = 0.0.0.0/0,::0/0
Endpoint = 123.45.67.89:51820
```

**Important Fields:**
- `Address`: Contains both IPv4 and **IPv6** address
  - IPv6 format: `fc00:bbbb:bbbb:bb01::X:XXXX/128`
  - Use the IPv6 address in v6-gatewayd config
- `Endpoint`: Mullvad server address
- `AllowedIPs`: `::0/0` enables IPv6 routing

## Multi-Location Setup

Configure multiple Mullvad servers for failover:

```ini
[tunnel1]
name = "mullvad-us-nyc"
type = "wireguard"
iface = "mullvad0"
v6_prefix = "fc00:bbbb:bbbb:bb01::1"
enabled = true
priority = 0

[tunnel2]
name = "mullvad-us-lax"
type = "wireguard"
iface = "mullvad1"
v6_prefix = "fc00:bbbb:bbbb:bb02::1"
enabled = true
priority = 1

[tunnel3]
name = "mullvad-eu-ams"
type = "wireguard"
iface = "mullvad2"
v6_prefix = "fc00:bbbb:bbbb:bb03::1"
enabled = true
priority = 2
```

**Setup multiple configs:**
```bash
# Copy configs
sudo cp mullvad-us-nyc-001.conf /etc/wireguard/mullvad0.conf
sudo cp mullvad-us-lax-001.conf /etc/wireguard/mullvad1.conf
sudo cp mullvad-eu-ams-001.conf /etc/wireguard/mullvad2.conf

# Set permissions
sudo chmod 600 /etc/wireguard/mullvad*.conf
```

v6-gatewayd will automatically:
- Monitor health of all tunnels
- Failover to backup if primary fails
- Select optimal tunnel based on latency

## Selecting Mullvad Servers

### Low Latency Servers

Test latency to find best servers:

```bash
# Install ping tool
sudo apt install iputils-ping

# Test Mullvad servers
# US East (New York)
ping -c 5 us-nyc-001.wg.mullvad.net

# US West (Los Angeles)
ping -c 5 us-lax-001.wg.mullvad.net

# Europe (Amsterdam)
ping -c 5 nl-ams-001.wg.mullvad.net

# Europe (Stockholm)
ping -c 5 se-sto-001.wg.mullvad.net

# Asia (Singapore)
ping -c 5 sg-sin-001.wg.mullvad.net
```

### Recommended Servers for Common Locations

| Location | Server | Typical Latency |
|----------|--------|-----------------|
| US East Coast | us-nyc-001 | 20-40ms |
| US West Coast | us-lax-001 | 10-30ms |
| Europe | nl-ams-001, se-sto-001 | 30-50ms |
| Asia Pacific | sg-sin-001, jp-tyo-001 | 50-100ms |

## IPv6 with Mullvad

### Mullvad IPv6 Ranges

Mullvad assigns IPv6 addresses from:
- Range: `fc00:bbbb:bbbb:bb01::/64` (and other bb0X ranges)
- Type: Unique Local Address (ULA)
- Privacy: Not routable on public internet (Mullvad NAT66)

### IPv6 Connectivity Check

```bash
# Check if you have IPv6
curl -6 https://am.i.mullvad.net/json

# Expected response:
{
  "ip": "fc00:bbbb:bbbb:bb01::X:XXXX",
  "country": "USA",
  "city": "New York",
  "mullvad_exit_ip": true,
  "mullvad_exit_ip_hostname": "us-nyc-001.mullvad.net",
  "organization": "M247 Ltd"
}
```

### Using Mullvad IPv6 with Applications

Applications can bind to your Mullvad IPv6 address:

```bash
# Get your Mullvad IPv6 address
MULLVAD_IPV6=$(curl -s http://localhost:8642/v6/address | jq -r '.addresses[0].address')

# I2P example - bind to Mullvad IPv6
# Edit i2prouter config:
i2p.router.net.i2p.router.transport.TransportImpl.host=$MULLVAD_IPV6

# Tor relay - advertise Mullvad IPv6
# torrc:
ORPort [${MULLVAD_IPV6}]:9001
```

## Security Considerations

### Kill Switch

Mullvad configs include a kill switch via `AllowedIPs = 0.0.0.0/0,::0/0`. If WireGuard goes down, no traffic leaks.

v6-gatewayd adds additional protection:
- Health monitoring detects tunnel failures
- Automatic failover to backup tunnels
- API reports connectivity status

### DNS Leaks

Mullvad provides DNS servers in the config (`DNS = 10.64.0.1`). Configure your system to use Mullvad DNS:

```bash
# Option 1: Use Mullvad DNS in /etc/resolv.conf
echo "nameserver 10.64.0.1" | sudo tee /etc/resolv.conf

# Option 2: Configure via NetworkManager
sudo nmcli connection modify <connection> ipv4.dns "10.64.0.1"
sudo nmcli connection modify <connection> ipv6.dns "fc00:bbbb:bbbb:bb01::1"
```

### Port Forwarding

Mullvad supports port forwarding on select servers (https://mullvad.net/en/help/port-forwarding-and-mullvad/):

1. Enable port forwarding in Mullvad app or website
2. Note your forwarded port (e.g., 51820)
3. Applications can use this port for inbound connections

## Troubleshooting

### Tunnel Won't Start

```bash
# Check WireGuard config syntax
sudo wg-quick up mullvad0

# Common errors:
# - Missing private key: Regenerate in Mullvad account
# - Invalid endpoint: Check server address
# - Permission denied: chmod 600 the config file
```

### No IPv6 Connectivity

```bash
# Verify IPv6 is in Mullvad config
grep "Address.*::" /etc/wireguard/mullvad0.conf

# Check WireGuard interface has IPv6
ip -6 addr show mullvad0

# Test IPv6 routing
ip -6 route show | grep mullvad0

# Ping IPv6 Google DNS
ping6 2001:4860:4860::8888
```

### High Latency

```bash
# Check tunnel health
curl http://localhost:8642/tunnels | jq

# View failover logs
sudo journalctl -u v6-gatewayd | grep -i failover

# Try different Mullvad server
# Download new config for closer location
```

### Mullvad Account Issues

```bash
# Check account status
curl https://am.i.mullvad.net/json

# If not showing Mullvad:
# 1. Check WireGuard is up: sudo wg show
# 2. Check account has time: https://mullvad.net/en/account
# 3. Regenerate WireGuard key if needed
```

## Performance Tuning

### WireGuard MTU

Optimize MTU for better performance:

```bash
# Edit Mullvad config
sudo nano /etc/wireguard/mullvad0.conf

# Add to [Interface] section:
MTU = 1420

# Or for lower latency (smaller packets):
MTU = 1280
```

### Multiple Connections

For high-bandwidth applications, use multiple Mullvad servers in parallel:

```ini
# v6-gatewayd.conf - all enabled, different priorities
[tunnel1]
name = "mullvad-us-nyc"
enabled = true
priority = 0

[tunnel2]
name = "mullvad-us-lax"
enabled = true
priority = 0  # Same priority = load balance

[tunnel3]
name = "mullvad-eu-ams"
enabled = true
priority = 1  # Backup
```

## API Integration

### Get Mullvad Status

```bash
# Check if connected to Mullvad
curl -s http://localhost:8642/tunnels | jq '.tunnels[] | select(.name | contains("mullvad"))'

# Get Mullvad IPv6 address
curl -s http://localhost:8642/v6/address | jq -r '.addresses[] | select(.iface | contains("mullvad")).address'

# Check tunnel health
curl -s http://localhost:8642/health
```

### Automated Monitoring

```bash
#!/bin/bash
# mullvad-monitor.sh - Check Mullvad connectivity every 60 seconds

while true; do
    # Check if connected via Mullvad
    IS_MULLVAD=$(curl -s https://am.i.mullvad.net/json | jq -r '.mullvad_exit_ip')

    if [ "$IS_MULLVAD" = "true" ]; then
        echo "$(date): Connected via Mullvad ✓"
    else
        echo "$(date): NOT connected via Mullvad ✗"
        # Restart tunnel
        sudo systemctl restart v6-gatewayd
    fi

    sleep 60
done
```

## Cost and Pricing

Mullvad pricing (as of 2024):
- €5/month (flat rate)
- No subscriptions - pay as you go
- Accepts: Credit card, PayPal, Bitcoin, Cash, Swish
- 5 simultaneous WireGuard connections per account

## Additional Resources

- Mullvad Website: https://mullvad.net
- WireGuard Docs: https://www.wireguard.com/
- Mullvad Server List: https://mullvad.net/en/servers
- Mullvad Guides: https://mullvad.net/en/help/
- v6-gatewayd GitHub: https://github.com/SWORDIntel/HURRICANE

## Example: I2P Over Mullvad

Complete setup for running I2P over Mullvad VPN with IPv6:

```bash
# 1. Set up Mullvad tunnel (already done above)

# 2. Get Mullvad IPv6 address
MULLVAD_IPV6=$(curl -s http://localhost:8642/v6/address | jq -r '.addresses[0].address')

# 3. Configure I2P to use Mullvad IPv6
# Edit ~/.i2p/router.config:
i2p.router.net.i2p.router.transport.ntcp.ipv6=$MULLVAD_IPV6

# 4. Start I2P
~/i2p/i2prouter start

# 5. Verify I2P is using Mullvad IPv6
curl -s http://127.0.0.1:7657/confignet | grep -i ipv6
```

Your I2P traffic now flows through Mullvad VPN with full IPv6 support!
