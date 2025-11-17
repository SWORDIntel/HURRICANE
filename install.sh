#!/bin/bash
# HURRICANE v6-gatewayd Unified Installation Script
# Installs all components: v6-gatewayd, FASTPORT, IPVNINER, dependencies

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║      HURRICANE v6-gatewayd Unified Installation          ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${RED}Error: Do not run this script as root${NC}"
   echo "Run as regular user. sudo will be requested when needed."
   exit 1
fi

# Detect package manager
if command -v apt-get &> /dev/null; then
    PKG_MGR="apt-get"
    UPDATE_CMD="sudo apt-get update"
    INSTALL_CMD="sudo apt-get install -y"
elif command -v yum &> /dev/null; then
    PKG_MGR="yum"
    UPDATE_CMD="sudo yum check-update || true"
    INSTALL_CMD="sudo yum install -y"
else
    echo -e "${RED}Error: No supported package manager found (apt-get or yum)${NC}"
    exit 1
fi

echo -e "${BLUE}[1/7] Updating package lists...${NC}"
$UPDATE_CMD

echo -e "${BLUE}[2/7] Installing system dependencies...${NC}"
SYSTEM_DEPS=(
    "build-essential"
    "git"
    "curl"
    "python3"
    "python3-pip"
    "python3-venv"
    "iproute2"
    "iptables"
    "net-tools"
)

if [[ "$PKG_MGR" == "yum" ]]; then
    SYSTEM_DEPS=("gcc" "gcc-c++" "make" "git" "curl" "python3" "python3-pip" "iproute" "iptables" "net-tools")
fi

for dep in "${SYSTEM_DEPS[@]}"; do
    if ! dpkg -l | grep -q "^ii  $dep" 2>/dev/null && ! rpm -q "$dep" &>/dev/null; then
        echo -e "  ${YELLOW}Installing $dep...${NC}"
        $INSTALL_CMD "$dep" || true
    fi
done

echo -e "${BLUE}[3/7] Installing Rust (for FASTPORT)...${NC}"
if ! command -v cargo &> /dev/null; then
    echo -e "  ${YELLOW}Installing Rust toolchain...${NC}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> "$HOME/.bashrc"
else
    echo -e "  ${GREEN}Rust already installed${NC}"
fi

echo -e "${BLUE}[4/7] Installing Python dependencies...${NC}"
pip3 install --user --upgrade pip
pip3 install --user Flask flask-cors requests asyncio aiohttp

echo -e "${BLUE}[5/7] Initializing git submodules (IPVNINER)...${NC}"
if [ -f .gitmodules ]; then
    git submodule update --init --recursive
    echo -e "  ${GREEN}Submodules initialized${NC}"
else
    echo -e "  ${YELLOW}No submodules configured${NC}"
fi

echo -e "${BLUE}[6/7] Building FASTPORT (Rust core)...${NC}"
if [ -d "fastport/fastport-core" ]; then
    cd fastport/fastport-core
    if [ -f Cargo.toml ]; then
        source "$HOME/.cargo/env" 2>/dev/null || true
        cargo build --release
        echo -e "  ${GREEN}FASTPORT built successfully${NC}"
    else
        echo -e "  ${YELLOW}FASTPORT Cargo.toml not found, skipping build${NC}"
    fi
    cd "$SCRIPT_DIR"
else
    echo -e "  ${YELLOW}FASTPORT source not found, skipping build${NC}"
fi

echo -e "${BLUE}[7/7] Installing HURRICANE scripts...${NC}"
sudo mkdir -p /usr/local/bin

# Install main control script
if [ -f "hurricane" ]; then
    sudo cp hurricane /usr/local/bin/hurricane
    sudo chmod +x /usr/local/bin/hurricane
    echo -e "  ${GREEN}Installed: hurricane (unified control)${NC}"
fi

# Install scanner scripts
for script in fastport-ipv6 fastport-unified; do
    if [ -f "$script" ]; then
        sudo cp "$script" /usr/local/bin/
        sudo chmod +x "/usr/local/bin/$script"
        echo -e "  ${GREEN}Installed: $script${NC}"
    fi
done

# Set execute permissions on local scripts
chmod +x scripts/*.py 2>/dev/null || true
chmod +x *.sh 2>/dev/null || true

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              Installation Complete!                       ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo -e "  1. Configure tunnels in ${YELLOW}config/tunnels/940962.toml${NC}"
echo -e "  2. Set credentials in ${YELLOW}config/credentials/940962.creds${NC}"
echo -e "  3. Start the system: ${GREEN}hurricane start${NC}"
echo -e "  4. Check status: ${GREEN}hurricane status${NC}"
echo -e "  5. Access WebUI: ${GREEN}http://127.0.0.1:8643${NC}"
echo ""
echo -e "${YELLOW}For help: hurricane --help${NC}"
echo ""
