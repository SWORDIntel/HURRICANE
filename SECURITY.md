# HURRICANE v6-gatewayd Security Architecture

## Overview

HURRICANE v6-gatewayd implements **defense-in-depth** security with multiple layers of protection:

1. **Post-Quantum Cryptography** (CNSA 2.0 compliant)
2. **Hardware Authentication** (Fingerprint + YubiKey)
3. **Multi-Factor Authentication** (MFA)
4. **Local-Only Access** (No remote exposure)

---

## CNSA 2.0 Compliance

The system implements **Commercial National Security Algorithm Suite 2.0** specifications:

### Post-Quantum Algorithms

| Algorithm | Purpose | Key Size |
|-----------|---------|----------|
| **ML-KEM-1024** | Key Encapsulation Mechanism | 1568 bytes (public), 3168 bytes (secret) |
| **ML-DSA-87** | Digital Signatures | 2592 bytes (public), 4896 bytes (secret) |
| **SHA-384** | Cryptographic Hashing | 384 bits |

### Implementation

- **liboqs** (Open Quantum Safe) for PQC primitives
- **OpenSSL** for classical crypto (AES-256-GCM, SHA-384)
- Fallback mode when liboqs unavailable (uses RSA-3072/ECDSA with OpenSSL)

###Key Management

```bash
# Generate CNSA 2.0 compliant keys
sudo v6gw-keygen -o /var/lib/v6-gatewayd/keys.bin

# Keys are stored with:
- File permissions: 0600 (owner read/write only)
- Magic header: "V6GW-CNSA2.0"
- Encrypted at rest with filesystem encryption (recommended)
```

---

## Hardware Authentication

### Supported Methods

1. **Fingerprint Reader** (via libfprint)
   - Biometric authentication
   - Local verification only
   - No fingerprint data transmitted

2. **YubiKey** (via libykpers)
   - FIDO U2F/U2F2 support
   - Challenge-response authentication
   - Hardware-backed secrets

### Configuration

```ini
[hwauth]
# Enable hardware authentication
enabled = true

# Required method: fingerprint, yubikey, or both
required_method = both

# Allow fallback to other methods
allow_fallback = true

# Authentication timeout (seconds)
timeout = 30
```

### PAM Integration

The system uses **PAM (Pluggable Authentication Modules)** for hardware auth:

```bash
# Install PAM configurations
sudo cp pam/v6-gatewayd-fingerprint /etc/pam.d/
sudo cp pam/v6-gatewayd-yubikey /etc/pam.d/
```

**Prerequisites:**
```bash
# For fingerprint support
sudo apt install libpam-fprintd fprintd

# For YubiKey support
sudo apt install libpam-yubico yubikey-personalization

# Enroll fingerprints
fprintd-enroll $USER

# Configure YubiKey
ykpersonalize -v
```

---

## Multi-Factor Authentication (MFA)

### Authentication Flow

1. **API/MCP Request** → Server receives connection
2. **Post-Quantum Key Exchange** → ML-KEM-1024 establishes shared secret
3. **Hardware Auth Challenge** → Fingerprint OR YubiKey required
4. **Token Signature** → ML-DSA-87 signs authentication token
5. **Session Established** → AES-256-GCM encrypted communications

### Session Management

- **Session Duration:** 1 hour (configurable)
- **Token Validity:** 24 hours (configurable)
- **Auto-Refresh:** Sessions renewed on activity
- **Secure Wipe:** All session data zeroed on logout

---

## API Security

### REST API (HTTP+JSON)

**Bind Address:** `127.0.0.1` only (localhost)

**Authentication:**
```http
POST /auth/login
Content-Type: application/json

{
  "username": "admin",
  "public_key": "<ML-KEM-1024 public key>",
  "hardware_auth_required": true
}

Response:
{
  "session_id": "<encrypted session ID>",
  "token": "<ML-DSA-87 signed token>",
  "expires": 1699564234
}
```

**Protected Endpoints:**
- All endpoints require valid session token
- Tokens verified with ML-DSA-87 signature check
- Automatic re-authentication after timeout

### MCP Server (Model Context Protocol)

**Socket:** `/var/run/v6-gatewayd-mcp.sock`

**Permissions:** `0600` (owner only)

**Security Features:**
- Unix socket (no network exposure)
- Peer credential verification
- JSON-RPC 2.0 with encrypted payloads
- Read-only operations (no state modifications)

---

## Threat Model

### Protected Against

✅ **Man-in-the-Middle** (MITM)
- Post-quantum key exchange prevents decryption
- ML-KEM-1024 resistant to Shor's algorithm

✅ **Replay Attacks**
- Timestamped tokens with short validity
- Session IDs include random nonces

✅ **Impersonation**
- Hardware authentication required
- Biometric/hardware key verification

✅ **Quantum Computer Attacks**
- CNSA 2.0 algorithms quantum-resistant
- Future-proof against quantum threats

✅ **Unauthorized Local Access**
- File permissions (0600)
- Unix socket ownership checks
- PAM-based authentication

### Attack Surface

**Minimal by Design:**
- No remote network exposure
- Local-only API (127.0.0.1)
- Unix socket with strict permissions
- Hardware authentication barrier

**Potential Risks:**
- Physical access to machine (mitigated by hw auth)
- Root compromise (system-level threat)
- Side-channel attacks on crypto (use constant-time implementations)

---

## Compliance & Standards

### CNSA 2.0 (NSA)
- ✅ ML-KEM-1024 for key establishment
- ✅ ML-DSA-87 for digital signatures
- ✅ SHA-384 for hashing
- ✅ AES-256 for symmetric encryption

### NIST Post-Quantum Standards
- ✅ FIPS 203 (ML-KEM) - Kyber
- ✅ FIPS 204 (ML-DSA) - Dilithium
- ✅ FIPS 202 (SHA-3 family)

### FIDO Alliance
- ✅ FIDO U2F support (YubiKey)
- ✅ WebAuthn compatible
- ✅ CTAP2 protocol

---

## Security Best Practices

### Deployment

1. **Enable Full Disk Encryption**
   ```bash
   # LUKS for Linux
   sudo cryptsetup luksFormat /dev/sdX
   ```

2. **Secure Key Storage**
   ```bash
   # Restrict permissions
   sudo chmod 600 /var/lib/v6-gatewayd/keys.bin
   sudo chown root:root /var/lib/v6-gatewayd/keys.bin

   # Optional: Store on encrypted partition
   sudo mount -t tmpfs -o size=1M,mode=0700 tmpfs /var/lib/v6-gatewayd
   ```

3. **Firewall Configuration**
   ```bash
   # Ensure API not exposed externally
   sudo ufw deny 8642
   sudo ufw allow from 127.0.0.1 to any port 8642
   ```

4. **Audit Logging**
   ```bash
   # Monitor authentication attempts
   sudo journalctl -u v6-gatewayd -f | grep -i auth
   ```

### Key Rotation

```bash
# Generate new keys
sudo v6gw-keygen -o /var/lib/v6-gatewayd/keys-new.bin

# Stop daemon
sudo systemctl stop v6-gatewayd

# Backup old keys
sudo mv /var/lib/v6-gatewayd/keys.bin /var/lib/v6-gatewayd/keys-old.bin

# Activate new keys
sudo mv /var/lib/v6-gatewayd/keys-new.bin /var/lib/v6-gatewayd/keys.bin

# Start daemon
sudo systemctl start v6-gatewayd

# Securely delete old keys
sudo shred -vfz -n 10 /var/lib/v6-gatewayd/keys-old.bin
```

### Monitoring

```bash
# Check security status
curl http://localhost:8642/security/status

Response:
{
  "crypto_enabled": true,
  "pqc_algorithms": ["ML-KEM-1024", "ML-DSA-87", "SHA-384"],
  "hardware_auth_enabled": true,
  "available_methods": ["fingerprint", "yubikey"],
  "active_sessions": 1,
  "last_auth_attempt": "2024-01-15T10:30:00Z"
}
```

---

## Incident Response

### Suspected Compromise

1. **Immediate Actions:**
   ```bash
   # Stop daemon
   sudo systemctl stop v6-gatewayd

   # Revoke all sessions
   sudo rm /var/run/v6-gatewayd-*.sock

   # Rotate keys
   sudo v6gw-keygen -f -o /var/lib/v6-gatewayd/keys.bin
   ```

2. **Investigation:**
   ```bash
   # Review logs
   sudo journalctl -u v6-gatewayd --since "1 hour ago"

   # Check for unauthorized access
   sudo last
   sudo lastlog
   ```

3. **Recovery:**
   - Verify system integrity
   - Re-enroll hardware authentication
   - Update all credentials
   - Resume operations

---

## References

- [CNSA 2.0 Specification](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [liboqs Documentation](https://github.com/open-quantum-safe/liboqs)
- [PAM Documentation](http://www.linux-pam.org/)
- [libfprint](https://fprint.freedesktop.org/)
- [YubiKey Documentation](https://www.yubico.com/documentation/)

---

**Last Updated:** 2024-01-15
**Security Contact:** security@yourdomain.com
**CVE Reporting:** Follow responsible disclosure guidelines
