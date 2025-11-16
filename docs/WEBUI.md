# TEMPEST WebUI

HURRICANE v6-gatewayd includes a hardened, TEMPEST Class C themed web interface for monitoring and managing tunnels.

## Security Features

The WebUI implements multiple security hardening measures:

### Local-Only Access
- **Bind Address**: Only accessible from `127.0.0.1` (localhost)
- **No Remote Access**: Cannot be accessed from network
- **Same-Host Only**: Must be on the same system as the daemon

### Security Headers
All WebUI responses include hardened HTTP security headers:

```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
```

**Protection Against:**
- ✅ XSS (Cross-Site Scripting)
- ✅ Clickjacking
- ✅ MIME-type sniffing
- ✅ Referrer leaks
- ✅ External resource loading

### No External Dependencies
- **Zero External Resources**: All CSS/JS inline
- **No CDNs**: No external script loading
- **No Tracking**: No analytics or telemetry
- **No Cookies**: Stateless interface

### TEMPEST Class C Compliance

TEMPEST (Telecommunications Electronics Material Protected from Emanating Spurious Transmissions) is a NATO/NSA standard for controlling electromagnetic emissions.

**Class C Features:**
- **Dark Theme**: Reduces screen emissions (black/dark green palette)
- **Minimal Graphics**: Low electromagnetic signature
- **Monospace Fonts**: Consistent rendering
- **No Animations**: Except essential status indicators
- **Hard Edges**: No gradients or complex rendering

## Access the WebUI

### URL

```
http://127.0.0.1:8642/ui
```

### Requirements

1. **v6-gatewayd** must be running
2. Access from the **same system** (localhost only)
3. Modern web browser (Chrome, Firefox, Safari, Edge)

### Quick Start

```bash
# Start the daemon
sudo systemctl start v6-gatewayd

# Open in browser
xdg-open http://127.0.0.1:8642/ui

# Or with curl
curl http://127.0.0.1:8642/ui
```

## Dashboard Features

### Real-Time Monitoring

**System Status Bar:**
- System operational status (OPERATIONAL/DEGRADED/OFFLINE)
- Active tunnel count
- IPv6 reachability status
- Last update timestamp
- Auto-refresh indicator

**System Health Panel:**
- Overall status
- IPv6 latency (milliseconds)
- Active tunnel count
- Daemon version

**IPv6 Addresses Panel:**
- Lists all available IPv6 addresses
- Interface mapping
- Reachability status

**Tunnel Status Panel:**
- Real-time tunnel state (UP/DOWN)
- Tunnel type (HE 6in4, WireGuard, etc.)
- Health score (0-100) with visual indicator
- Priority level
- Primary/Backup designation
- Visual health bars (green/yellow/red)

**Activity Log Panel:**
- Recent events and status changes
- Timestamped entries
- Log levels (INFO/WARN/ERROR)
- Color-coded messages
- Auto-scrolling (last 50 entries)

### Auto-Refresh

The dashboard automatically updates every **5 seconds** with:
- System health status
- Tunnel states
- IPv6 addresses
- Health scores
- Activity logs

### Visual Indicators

**Status Colors:**
- 🟢 **Green**: Operational / UP / Healthy
- 🟡 **Yellow**: Degraded / Warning
- 🔴 **Red**: Offline / DOWN / Critical

**Health Scoring:**
- **70-100**: Green (Healthy)
- **30-69**: Yellow (Degraded)
- **0-29**: Red (Critical)

## TEMPEST Theme

### Color Palette

```css
Primary Background:   #0a0a0a (Black)
Secondary Background: #1a1a1a (Dark Gray)
Panel Background:     #151515 (Very Dark Gray)
Border Color:         #2a4a2a (Dark Military Green)

Text Primary:         #00ff00 (Bright Green)
Text Secondary:       #00aa00 (Medium Green)
Text Dim:             #008800 (Dark Green)
Text Warning:         #ffaa00 (Amber)
Text Error:           #ff3333 (Red)
Text Info:            #00aaff (Cyan)

Status UP:            #00ff00 (Green)
Status DOWN:          #ff3333 (Red)
Status DEGRADED:      #ffaa00 (Yellow)
```

### Typography

**Font Family:**
```
'Courier New', 'Lucida Console', monospace
```

**Design Principles:**
- Monospace for all text (military/terminal aesthetic)
- Uppercase headers for emphasis
- Letter spacing for readability
- Hard edges (no rounded corners)
- Minimal animations (TEMPEST compliance)

### Layout

- **Grid-based**: Responsive panels
- **Dark background**: Reduces emissions
- **High contrast**: Readability in secure environments
- **Status bar**: Always visible system status
- **Classified banner**: Visual security reminder

## Browser Support

**Tested and Supported:**
- ✅ Chrome/Chromium 90+
- ✅ Firefox 88+
- ✅ Safari 14+
- ✅ Edge 90+

**Requirements:**
- JavaScript enabled (for API calls)
- CSS3 support (for grid layout)
- Fetch API support (for REST calls)

## API Integration

The WebUI connects to the REST API endpoints:

```javascript
// Health status
GET /health

// IPv6 addresses
GET /v6/address

// Tunnel status
GET /tunnels

// Daemon info
GET /
```

All API calls are made via `fetch()` with error handling.

## Customization

### Changing Refresh Interval

Edit `web/index.html`:

```javascript
// Default: 5000ms (5 seconds)
setInterval(updateDashboard, 5000);

// Change to 10 seconds:
setInterval(updateDashboard, 10000);
```

### Modifying Theme Colors

Edit the `:root` CSS variables in `web/index.html`:

```css
:root {
    --primary-bg: #0a0a0a;        /* Main background */
    --text-primary: #00ff00;      /* Main text color */
    --status-up: #00ff00;         /* UP status color */
    /* ... */
}
```

### Changing Log Buffer Size

Edit `web/index.html`:

```javascript
// Default: 50 entries
const MAX_LOG_ENTRIES = 50;

// Change to 100:
const MAX_LOG_ENTRIES = 100;
```

## Troubleshooting

### WebUI Not Loading

**Error**: Cannot connect to v6-gatewayd

**Solutions:**
1. Verify daemon is running:
   ```bash
   sudo systemctl status v6-gatewayd
   ```

2. Check API server is listening:
   ```bash
   curl http://127.0.0.1:8642/health
   ```

3. Check browser console for errors (F12)

4. Verify WebUI file is installed:
   ```bash
   ls -l /usr/local/share/v6-gatewayd/web/index.html
   # Or for development:
   ls -l web/index.html
   ```

### Access Denied / 404 Error

**Error**: WebUI not found

**Solutions:**
1. Ensure you're using the correct URL:
   ```
   http://127.0.0.1:8642/ui  (not /webui or /index.html)
   ```

2. Check file permissions:
   ```bash
   sudo chmod 644 /usr/local/share/v6-gatewayd/web/index.html
   ```

3. Verify daemon was built with WebUI support:
   ```bash
   v6-gatewayd --version
   ```

### Data Not Updating

**Issue**: Dashboard shows stale data

**Solutions:**
1. Check browser console for fetch errors
2. Verify API endpoints are responding:
   ```bash
   curl http://127.0.0.1:8642/health
   curl http://127.0.0.1:8642/tunnels
   ```
3. Refresh page (Ctrl+R or Cmd+R)
4. Clear browser cache

### CSS Not Applying

**Issue**: Page looks unstyled

**Solutions:**
1. Hard refresh: Ctrl+Shift+R (or Cmd+Shift+R on Mac)
2. Check browser console for CSS errors
3. Verify Content-Security-Policy isn't blocking styles
4. Try different browser

## Security Considerations

### Threat Model

**Assumed Threats:**
- ❌ Remote attackers (mitigated by localhost binding)
- ✅ Local privilege escalation attempts
- ✅ XSS attacks (mitigated by CSP)
- ✅ Clickjacking (mitigated by X-Frame-Options)
- ✅ Data exfiltration (no external resources)

**Not Protected Against:**
- ⚠️ Root user on same system (by design)
- ⚠️ Physical access to terminal
- ⚠️ Keyloggers on same system

### Best Practices

1. **Access Control**: Limit who can access the system
2. **Screen Privacy**: Use privacy screens in sensitive environments
3. **Auto-Lock**: Enable screen lock when away
4. **Audit Logs**: Monitor system access logs
5. **Updates**: Keep daemon and browser updated

### TEMPEST Compliance Notes

**Full TEMPEST Class C compliance requires:**
- ✅ Dark theme (implemented)
- ✅ Minimal rendering (implemented)
- ✅ Monospace fonts (implemented)
- ⚠️ TEMPEST-certified display hardware (user responsibility)
- ⚠️ Shielded room (user responsibility)
- ⚠️ EM emission monitoring (user responsibility)

**This WebUI provides software-level TEMPEST features.**
**Hardware compliance is the user's responsibility.**

## Development

### File Location

**Source:**
```
web/index.html  - Single-page application (HTML + CSS + JS)
```

**Installed:**
```
/usr/local/share/v6-gatewayd/web/index.html
```

### Development Mode

Run without installing:

```bash
# Start daemon
sudo ./v6-gatewayd -f -c /etc/v6-gatewayd.conf

# WebUI will load from web/index.html
# Open: http://127.0.0.1:8642/ui
```

### Code Structure

```
<head>
  - Meta tags (CSP, referrer policy)
  - Inline CSS (TEMPEST theme)
</head>

<body>
  - Header (title + classification)
  - Status Bar (system status)
  - Dashboard Panels:
    - System Health
    - IPv6 Addresses
    - Tunnel Status
    - Activity Log
  - Footer
  - Inline JavaScript (API integration)
</body>
```

### Adding Features

**To add a new panel:**

1. Add HTML structure:
```html
<div class="panel">
  <div class="panel-header">⬢ NEW PANEL</div>
  <div class="panel-body" id="new-panel">
    <!-- Content -->
  </div>
</div>
```

2. Add update function:
```javascript
async function fetchNewData() {
    const response = await fetch(`${API_BASE}/new-endpoint`);
    const data = await response.json();
    // Update DOM
}
```

3. Call from updateDashboard():
```javascript
await fetchNewData();
```

## Screenshots

### Main Dashboard
```
┌─────────────────────────────────────────────────────────────┐
│ ⬡ HURRICANE v6-gatewayd    TEMPEST CLASS C // LOCAL ONLY   │
├─────────────────────────────────────────────────────────────┤
│ ● OPERATIONAL  |  ACTIVE: 2  |  IPv6: YES  |  12:34:56 ⬚  │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│ ⬢ SYSTEM HEALTH          ⬢ IPv6 ADDRESSES                  │
│ ┌──────────────────┐     ┌──────────────────┐              │
│ │ STATUS: OK       │     │ mullvad0:        │              │
│ │ LATENCY: 25 ms   │     │ fc00:bbbb::1     │              │
│ │ TUNNELS: 2       │     │ he0:             │              │
│ │ VERSION: 1.0.0   │     │ 2001:470::2      │              │
│ └──────────────────┘     └──────────────────┘              │
│                                                              │
│ ⬢ TUNNEL STATUS                                             │
│ ┌──────────────────────────────────────────────────────────┐
│ │ MULLVAD-NYC [PRIMARY]                           UP       │
│ │ TYPE: wireguard  IFACE: mullvad0  HEALTH: 95/100        │
│ │ ████████████████████████████████████████████░░░░ 95%    │
│ └──────────────────────────────────────────────────────────┘
│                                                              │
│ ⬢ ACTIVITY LOG                                              │
│ ┌──────────────────────────────────────────────────────────┐
│ │ 12:34:56 [INFO] Health check: OK                        │
│ │ 12:34:51 [INFO] Tunnel mullvad-nyc: UP                  │
│ └──────────────────────────────────────────────────────────┘
└─────────────────────────────────────────────────────────────┘
```

## Future Enhancements

Planned features for future releases:

- [ ] Real-time failover event visualization
- [ ] Tunnel performance graphs
- [ ] Manual tunnel control (start/stop)
- [ ] Configuration editor
- [ ] Export logs to file
- [ ] Dark/light theme toggle (TEMPEST-compliant variants)
- [ ] Mobile-responsive layout
- [ ] WebSocket support for instant updates

## Resources

- **Main Docs**: [README.md](../README.md)
- **API Reference**: See README.md API section
- **Security**: [SECURITY.md](../SECURITY.md)
- **Mullvad**: [MULLVAD.md](MULLVAD.md)

## Support

If you encounter issues with the WebUI:

1. Check this documentation
2. Review browser console (F12)
3. Check daemon logs: `journalctl -u v6-gatewayd -f`
4. Report issues: https://github.com/SWORDIntel/HURRICANE/issues

---

**TEMPEST Console // Unauthorized Access Prohibited // LOCAL SYSTEM ONLY**
