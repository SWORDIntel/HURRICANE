#!/bin/bash
# Hurricane Electric Credentials Encryption Tool
# Encrypts HE credentials using AES-256-CBC with machine-specific key

set -e

CREDS_FILE="/etc/v6-gatewayd-he.env"
ENCRYPTED_FILE="/etc/v6-gatewayd-he.env.enc"
KEY_FILE="/var/lib/v6-gatewayd/he.key"

# SWORD HQ Tunnel Credentials
HE_USERNAME="SWORDIntel"
HE_PASSWORD="dokuchayev"
HE_TUNNEL_ID="940962"

usage() {
    echo "Usage: $0 [encrypt|decrypt|install]"
    echo ""
    echo "Commands:"
    echo "  encrypt  - Encrypt credentials file"
    echo "  decrypt  - Decrypt and display credentials"
    echo "  install  - Create and encrypt credentials (first-time setup)"
    exit 1
}

generate_key() {
    # Generate machine-specific encryption key
    # Uses machine-id + hostname for uniqueness
    local machine_id=$(cat /etc/machine-id 2>/dev/null || echo "default-machine")
    local hostname=$(hostname)

    # Create deterministic but unique key
    echo -n "${machine_id}${hostname}HURRICANE-HE-KEY" | sha256sum | cut -d' ' -f1
}

install_credentials() {
    echo "Installing encrypted Hurricane Electric credentials..."

    # Ensure directories exist
    mkdir -p /var/lib/v6-gatewayd
    mkdir -p /etc

    # Generate encryption key
    local key=$(generate_key)
    echo -n "$key" > "$KEY_FILE"
    chmod 600 "$KEY_FILE"

    # Create credentials file
    cat > "$CREDS_FILE" << EOF
# Hurricane Electric Tunnel Broker Credentials
# Pre-configured for SWORD HQ Tunnel (ID: 940962)
HE_USERNAME=$HE_USERNAME
HE_PASSWORD=$HE_PASSWORD
HE_TUNNEL_ID=$HE_TUNNEL_ID
EOF

    chmod 600 "$CREDS_FILE"

    # Encrypt credentials
    openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
        -in "$CREDS_FILE" \
        -out "$ENCRYPTED_FILE" \
        -pass "file:$KEY_FILE"

    # Remove plaintext
    rm -f "$CREDS_FILE"

    chmod 600 "$ENCRYPTED_FILE"

    echo "✓ Credentials encrypted and stored in: $ENCRYPTED_FILE"
    echo "✓ Encryption key stored in: $KEY_FILE"
    echo "✓ Plaintext credentials removed"
    echo ""
    echo "Credentials installed:"
    echo "  Username: $HE_USERNAME"
    echo "  Tunnel ID: $HE_TUNNEL_ID"
    echo "  Password: ********"
}

encrypt_credentials() {
    if [ ! -f "$CREDS_FILE" ]; then
        echo "Error: Credentials file not found: $CREDS_FILE"
        exit 1
    fi

    # Generate encryption key
    local key=$(generate_key)
    echo -n "$key" > "$KEY_FILE"
    chmod 600 "$KEY_FILE"

    # Encrypt
    openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
        -in "$CREDS_FILE" \
        -out "$ENCRYPTED_FILE" \
        -pass "file:$KEY_FILE"

    chmod 600 "$ENCRYPTED_FILE"

    echo "✓ Credentials encrypted: $ENCRYPTED_FILE"
}

decrypt_credentials() {
    if [ ! -f "$ENCRYPTED_FILE" ]; then
        echo "Error: Encrypted credentials not found: $ENCRYPTED_FILE"
        exit 1
    fi

    if [ ! -f "$KEY_FILE" ]; then
        echo "Error: Encryption key not found: $KEY_FILE"
        exit 1
    fi

    # Decrypt and display
    openssl enc -aes-256-cbc -d -pbkdf2 -iter 100000 \
        -in "$ENCRYPTED_FILE" \
        -pass "file:$KEY_FILE"
}

# Main
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root"
    exit 1
fi

case "${1:-}" in
    install)
        install_credentials
        ;;
    encrypt)
        encrypt_credentials
        ;;
    decrypt)
        decrypt_credentials
        ;;
    *)
        usage
        ;;
esac
