# Authentication Flow Documentation

## Overview

HURRICANE v6-gatewayd implements multi-layer authentication with:
- **Post-Quantum Cryptography** (ML-KEM-1024 key exchange)
- **Hardware Authentication** (Fingerprint OR YubiKey)
- **Session Management** (Encrypted tokens with ML-DSA-87 signatures)

---

## Authentication Flow

### 1. Initial Setup

```bash
# Generate CNSA 2.0 keys
sudo v6gw-keygen -o /var/lib/v6-gatewayd/keys.bin

# Enable crypto in config
sudo nano /etc/v6-gatewayd.conf
# Set: crypto_enabled = true

# Start daemon
sudo systemctl start v6-gatewayd
```

### 2. Login (POST /auth/login)

**Request:**
```http
POST /auth/login HTTP/1.1
Host: localhost:8642
Content-Type: application/json

{
  "username": "admin"
}
```

**Process:**
1. Server validates username
2. **Hardware authentication prompt:**
   - Place finger on fingerprint reader, OR
   - Touch YubiKey
3. ML-KEM-1024 generates shared secret
4. Session created with encrypted token
5. ML-DSA-87 signs authentication token

**Response:**
```json
{
  "status": "authenticated",
  "username": "admin",
  "session_id": "a3f8c9d2e5b1...",
  "auth_method": "fingerprint",
  "expires": 1699564234
}
```

### 3. Authenticated Requests

**Use session_id in Authorization header:**

```http
GET /tunnels HTTP/1.1
Host: localhost:8642
Authorization: Bearer a3f8c9d2e5b1...
```

**Process:**
1. Server extracts session_id from Authorization header
2. Validates session (checks expiration, crypto signature)
3. Updates last_activity and request_count
4. Processes request
5. Returns response

### 4. Check Auth Status (GET /auth/status)

```http
GET /auth/status HTTP/1.1
Host: localhost:8642
Authorization: Bearer a3f8c9d2e5b1...
```

**Response:**
```json
{
  "authenticated": true,
  "username": "admin",
  "auth_method": "fingerprint",
  "created": 1699560000,
  "expires": 1699563600,
  "last_activity": 1699562000,
  "request_count": 42
}
```

### 5. Logout (POST /auth/logout)

```http
POST /auth/logout HTTP/1.1
Host: localhost:8642
Authorization: Bearer a3f8c9d2e5b1...
```

**Response:**
```json
{
  "status": "logged_out"
}
```

---

## Session Management

### Session Properties

- **Duration:** 1 hour (3600 seconds)
- **Auto-Refresh:** Extended when <10 minutes remaining
- **Max Sessions:** 64 concurrent sessions
- **Cleanup:** Expired sessions removed every 5 minutes

### Session Security

- Session ID derived from ML-KEM-1024 shared secret
- All session data encrypted with AES-256-GCM
- Authentication tokens signed with ML-DSA-87
- Secure wipe on logout (memset to zero)

---

## Protected Endpoints

### Require Authentication

When `crypto_enabled = true`, these endpoints require valid session:

- `GET /v6/address` - IPv6 addresses
- `GET /tunnels` - Tunnel status

### Public Endpoints

Always accessible (no authentication required):

- `GET /` - Service info
- `GET /health` - System health
- `POST /auth/login` - Login
- `POST /auth/logout` - Logout
- `GET /auth/status` - Auth status

---

## Hardware Authentication

### Supported Methods

1. **Fingerprint** (via fprintd)
   ```bash
   # Enroll fingerprint
   fprintd-enroll $USER

   # Test enrollment
   fprintd-verify
   ```

2. **YubiKey** (via PAM-Yubico)
   ```bash
   # Insert YubiKey and configure
   ykpersonalize -v

   # Test YubiKey
   ykchalresp -t
   ```

### Configuration

Required method configured in main.c:
```c
hwauth_config_t hwauth_config = {
    .required_methods = HWAUTH_TYPE_BOTH,  // Fingerprint OR YubiKey
    .allow_fallback = true,
    .timeout_seconds = 30
};
```

---

## Error Codes

| Code | Meaning | Action |
|------|---------|--------|
| 200 | OK | Request successful |
| 400 | Bad Request | Check request format |
| 401 | Unauthorized | Login required or session expired |
| 404 | Not Found | Endpoint doesn't exist |
| 405 | Method Not Allowed | Wrong HTTP method |
| 500 | Internal Server Error | Server-side crypto failure |
| 503 | Service Unavailable | Crypto not initialized |

---

## Example: Complete Authentication Session

```bash
# 1. Login with hardware auth
curl -X POST http://localhost:8642/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin"}'

# (Touch fingerprint or YubiKey when prompted)

# Response:
# {
#   "status": "authenticated",
#   "session_id": "a3f8c9d2e5b1f4a7c8d9e0f1a2b3c4d5",
#   "auth_method": "fingerprint",
#   "expires": 1699564234
# }

# 2. Use session_id for authenticated requests
SESSION_ID="a3f8c9d2e5b1f4a7c8d9e0f1a2b3c4d5"

curl http://localhost:8642/tunnels \
  -H "Authorization: Bearer $SESSION_ID"

curl http://localhost:8642/v6/address \
  -H "Authorization: Bearer $SESSION_ID"

# 3. Check auth status
curl http://localhost:8642/auth/status \
  -H "Authorization: Bearer $SESSION_ID"

# 4. Logout
curl -X POST http://localhost:8642/auth/logout \
  -H "Authorization: Bearer $SESSION_ID"
```

---

## Security Notes

### Session ID Format

- 32 bytes (256 bits) of entropy
- Hex-encoded (64 characters)
- Derived from ML-KEM-1024 shared secret + timestamp
- Hashed with SHA-384

### Cryptographic Operations

1. **Key Exchange:** ML-KEM-1024 (post-quantum resistant)
2. **Digital Signatures:** ML-DSA-87 (post-quantum resistant)
3. **Hashing:** SHA-384 (384-bit output)
4. **Symmetric Encryption:** AES-256-GCM

### Attack Mitigation

- **Replay Attacks:** Timestamped tokens with expiration
- **Session Hijacking:** Cryptographic binding to hardware auth
- **Brute Force:** 256-bit entropy session IDs
- **Quantum Attacks:** CNSA 2.0 post-quantum algorithms

---

## Troubleshooting

### "Authentication not available"

**Cause:** Crypto not initialized

**Solution:**
```bash
# Check config
grep crypto_enabled /etc/v6-gatewayd.conf

# Generate keys if missing
sudo v6gw-keygen -o /var/lib/v6-gatewayd/keys.bin

# Restart daemon
sudo systemctl restart v6-gatewayd
```

### "Hardware authentication required"

**Cause:** No fingerprint or YubiKey detected

**Solution:**
```bash
# Check fingerprint reader
fprintd-list $USER

# Check YubiKey
lsusb | grep Yubico

# Enroll fingerprint
fprintd-enroll $USER
```

### "Session not found" / "Session expired"

**Cause:** Session expired (>1 hour) or invalid session_id

**Solution:**
```bash
# Login again
curl -X POST http://localhost:8642/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin"}'
```

---

## Development & Testing

### Disable Authentication (Testing Only)

```ini
# /etc/v6-gatewayd.conf
[crypto]
crypto_enabled = false
```

**WARNING:** All endpoints become public - use only for development!

### Session Inspection

```bash
# Check active sessions (requires daemon debug mode)
sudo journalctl -u v6-gatewayd | grep "Created session"
sudo journalctl -u v6-gatewayd | grep "Destroying session"
```

### Manual Session Cleanup

```bash
# Sessions auto-cleanup every 5 minutes
# To force cleanup, restart daemon:
sudo systemctl restart v6-gatewayd
```

---

## References

- [CNSA 2.0 Specification](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)
- [ML-KEM (Kyber) - NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
- [ML-DSA (Dilithium) - NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
- [Session Management Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

---

**Last Updated:** 2024-11-16
