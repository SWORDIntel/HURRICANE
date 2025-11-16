Here’s a clean brief you can hand to “future you” or another dev and actually build from.

---

## SITREP

* You’re behind residential IPv4 NAT, but you can establish outbound tunnels (e.g. HE 6in4, WireGuard, etc.).
* Tunnel providers give you **real IPv6** with no inbound firewalling.
* You want a **programmatic gateway** so I2P (and other apps) can easily use that IPv6, without you hand-crafting tunnel configs every time.

---

## Objective

Design **`v6-gatewayd`**: a small daemon that:

1. Brings up and monitors one or more IPv6-over-IPv4 tunnels.
2. Exposes a **local interface & API** that apps (I2P, Tor, whatever) can use to:

   * Get **reachable IPv6 endpoints**.
   * Map local ports/flows → external IPv6.
   * Query reachability status and metrics.

Keep it OS-level first (use kernel routing where possible), with optional userspace proxy mode.

---

## High-Level Architecture

### Components

1. **Core Daemon (`v6-gatewayd`)**

   * Runs as a systemd service.
   * Manages tunnel backends and health checks.
   * Owns config, state, logs, metrics.

2. **Tunnel Backends**

   * **Backend: HE 6in4**

     * Configures `sit`/`ipip` interface, addresses from /64.
     * Adds required routes.
   * **Backend: WireGuard/OpenVPN (optional)**

     * Reads static config, ensures interface is up.
   * **Backend: “External”**

     * Uses preexisting interface (e.g. `he-ipv6`) and just monitors.

3. **Exposure Modes (Data Plane for apps)**

   * **Mode A – Kernel-native (recommended)**

     * Daemon just ensures IPv6 interface is up.
     * Apps bind directly to IPv6 addresses.
   * **Mode B – UDP/TCP Proxy**

     * Daemon exposes local:

       * UDP relay: `127.0.0.1:port` ⇄ `v6-addr:port`
       * TCP relay: `127.0.0.1:port` ⇄ `v6-addr:port`
   * **Mode C – SOCKS5**

     * Daemon exposes a **SOCKS5 proxy** that prefers IPv6.
     * Any app that speaks SOCKS uses it.

4. **Control Plane API**

   * Local **HTTP+JSON** or **Unix socket**.
   * Provides discovery + control for the above.

---

## Primary I2P Flow

### Normal / Preferred Flow (Mode A)

1. `v6-gatewayd`:

   * Brings up HE tunnel (`he0`).
   * Assigns `2001:470:xxxx:yyyy::2/64` to `he0`.
   * Ensures routing is correct.

2. I2P:

   * Enables IPv6 transport.
   * Binds to `::` or explicitly to `2001:470:xxxx:yyyy::2`.
   * Uses its normal reachability tests over IPv6.

3. `v6-gatewayd` API:

   * Provides “health” for I2P to optionally query:

     * Is `he0` up?
     * Can we ping external v6?
     * Is UDP port X reachable from outside (self-test via remote probe)?

### Alternate / Locked-down Flow (Mode B: UDP proxy)

For environments where you can’t/shouldn’t expose OS IPv6 globally:

1. `v6-gatewayd`:

   * Creates UDP listener on `127.0.0.1:<local_port>`.
   * For every incoming datagram:

     * Looks up mapping: `<local_port> → <remote v6 addr:port>`.
     * Sends via HE tunnel as IPv6 UDP.

2. I2P:

   * Configured to think its “external address” is `127.0.0.1:<local_port>`.
   * All traffic hits the proxy; proxy rewrites and forwards to v6.

(Mode B is more complex and less efficient than just using kernel v6; worth having as a fallback but not the default.)

---

## Control Plane API Design

Expose a local REST/JSON API (or Unix-socket equivalent):

Base: `http://127.0.0.1:8642/` or `unix:/run/v6-gatewayd.sock`

### 1. Tunnel Management

* `GET /tunnels`

  * Returns list of tunnels, state, metrics.
* `POST /tunnels/{name}/up`
* `POST /tunnels/{name}/down`

### 2. Address Allocation / Info

* `GET /v6/address`

  * Returns:

    ```json
    {
      "iface": "he0",
      "address": "2001:470:xxxx:yyyy::2",
      "prefix": 64,
      "reachable": true,
      "latency_ms": 35
    }
    ```

* `POST /ports/udp`

  * Body:

    ```json
    {
      "internal_port": 7654,
      "external_port": 7654,
      "description": "I2P-UDP"
    }
    ```
  * For Mode B, sets up the local UDP relay mapping and starts listening.

### 3. Health / Diagnostics

* `GET /health`

  * Global tunnel and v6 connectivity status.
* `GET /probe/udp?port=7654`

  * Initiates self-test (optionally via remote probe service) to verify inbound UDP reachability on the v6 address.

---

## Config Sketch

Example `/etc/v6-gatewayd.toml`:

```toml
[core]
log_level = "info"
state_dir = "/var/lib/v6-gatewayd"

[tunnel.he]
type = "he_6in4"
endpoint_ipv4 = "X.Y.Z.W"        # HE server
local_ipv4 = "A.B.C.D"           # your WAN address
v6_prefix = "2001:470:xxxx:yyyy::"
prefix_len = 64

[exposure]
mode = "kernel"                  # "kernel" | "proxy" | "socks5"

[exposure.socks5]
bind = "127.0.0.1:1080"

[exposure.proxy]
udp_base_port = 40000
tcp_base_port = 41000
```

---

## Security & Abuse Controls

* API authentication:

  * Unix socket only **or**
  * HTTP on 127.0.0.1 with token header or mTLS.
* Per-client limits:

  * Max ports per process/user.
  * Max bandwidth, conn rate.
* Logging:

  * Structured logs with timestamps, interface, ports, volume.
  * Explicit warning about abuse risk if exposing generic IPv6 exit.

Challenge to the idea (on purpose):
If **you** own the box and can configure the OS, the *cleanest* solution is:

> “Program that manages tunnels + exposes a health/status API, while apps use plain IPv6 via the OS.”

The full-blown proxy modes are interesting but only necessary if:

* You don’t control OS networking, or
* You want to sandbox which apps get v6 (e.g. only I2P via a specific proxy port).

---

## MVP Checklist

1. **HE 6in4 backend**:

   * Bring up/down interface, assign v6, route, keepalive.
2. **Health checks**:

   * IPv6 ping to known hosts.
3. **REST API (read-only)**:

   * `/health`, `/v6/address`, `/tunnels`.
4. **Mode A only**:

   * No SOCKS/proxy yet; just orchestration.

Once that works cleanly with I2P by binding to the v6, add:

5. UDP proxy (Mode B) for constrained setups.
6. SOCKS5 mode for generic apps.

If you want, next step I can draft the actual `v6-gatewayd` directory layout + minimal Rust or Go skeleton that implements the health API and HE tunnel management.
