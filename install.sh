#!/bin/bash
# HURRICANE v6-gatewayd Unified Installation Script
# Installs all components: v6-gatewayd, FASTPORT, IPVNINER, dependencies
# Supports both Docker and native installation modes

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Virtual environment path
VENV_DIR="$SCRIPT_DIR/.venv"

print_banner() {
    clear
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║       HURRICANE v6-gatewayd Unified Installation          ║${NC}"
    echo -e "${GREEN}║         IPv6/IPv9 Dual-Stack Gateway System               ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_menu() {
    echo -e "${CYAN}Select installation mode:${NC}"
    echo ""
    echo -e "  ${BOLD}${YELLOW}[1]${NC}  ${BOLD}Native Installation${NC}"
    echo -e "       Install directly on your system with Python venv"
    echo -e "       ${CYAN}Best for:${NC} Development, customization, bare metal"
    echo ""
    echo -e "  ${BOLD}${YELLOW}[2]${NC}  ${BOLD}Docker Installation${NC}"
    echo -e "       Run in isolated containers with Docker Compose"
    echo -e "       ${CYAN}Best for:${NC} Quick setup, isolation, production"
    echo ""
    echo -e "  ${BOLD}${YELLOW}[3]${NC}  ${BOLD}Update Dependencies Only${NC}"
    echo -e "       Update Python packages and Rust components"
    echo ""
    echo -e "  ${BOLD}${YELLOW}[0]${NC}  ${BOLD}Exit${NC}"
    echo ""
}

# Check if running as root
check_not_root() {
    if [[ $EUID -eq 0 ]]; then
        echo -e "${RED}Error: Do not run this script as root${NC}"
        echo "Run as regular user. sudo will be requested when needed."
        exit 1
    fi
}

# Detect package manager
detect_pkg_manager() {
    if command -v apt-get &> /dev/null; then
        PKG_MGR="apt-get"
        UPDATE_CMD="sudo apt-get update"
        INSTALL_CMD="sudo apt-get install -y"
    elif command -v dnf &> /dev/null; then
        PKG_MGR="dnf"
        UPDATE_CMD="sudo dnf check-update || true"
        INSTALL_CMD="sudo dnf install -y"
    elif command -v yum &> /dev/null; then
        PKG_MGR="yum"
        UPDATE_CMD="sudo yum check-update || true"
        INSTALL_CMD="sudo yum install -y"
    elif command -v pacman &> /dev/null; then
        PKG_MGR="pacman"
        UPDATE_CMD="sudo pacman -Sy"
        INSTALL_CMD="sudo pacman -S --noconfirm"
    else
        echo -e "${RED}Error: No supported package manager found${NC}"
        exit 1
    fi
}

install_system_deps() {
    echo -e "${BLUE}[1/7] Updating package lists...${NC}"
    $UPDATE_CMD || true

    echo -e "${BLUE}[2/7] Installing system dependencies...${NC}"

    case "$PKG_MGR" in
        apt-get)
            SYSTEM_DEPS=("build-essential" "git" "curl" "wget" "python3" "python3-pip" "python3-venv" "python3-full" "iproute2" "iptables" "net-tools" "libssl-dev" "pkg-config")
            ;;
        dnf|yum)
            SYSTEM_DEPS=("gcc" "gcc-c++" "make" "git" "curl" "wget" "python3" "python3-pip" "python3-virtualenv" "iproute" "iptables" "net-tools" "openssl-devel")
            ;;
        pacman)
            SYSTEM_DEPS=("base-devel" "git" "curl" "wget" "python" "python-pip" "python-virtualenv" "iproute2" "iptables" "net-tools" "openssl")
            ;;
    esac

    for dep in "${SYSTEM_DEPS[@]}"; do
        echo -e "  ${YELLOW}Checking $dep...${NC}"
        $INSTALL_CMD "$dep" 2>/dev/null || true
    done
    echo -e "  ${GREEN}System dependencies installed${NC}"
}

install_rust() {
    echo -e "${BLUE}[3/7] Installing Rust (for FASTPORT)...${NC}"
    if ! command -v cargo &> /dev/null; then
        echo -e "  ${YELLOW}Installing Rust toolchain...${NC}"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
        echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> "$HOME/.bashrc"
    else
        echo -e "  ${GREEN}Rust already installed${NC}"
    fi
}

setup_python_venv() {
    echo -e "${BLUE}[4/7] Setting up Python virtual environment...${NC}"

    # Create virtual environment
    if [ ! -d "$VENV_DIR" ]; then
        echo -e "  ${YELLOW}Creating virtual environment at $VENV_DIR...${NC}"
        python3 -m venv "$VENV_DIR"
    else
        echo -e "  ${GREEN}Virtual environment already exists${NC}"
    fi

    # Activate and install dependencies
    echo -e "  ${YELLOW}Installing Python packages...${NC}"
    source "$VENV_DIR/bin/activate"

    pip install --upgrade pip
    pip install Flask flask-cors requests aiohttp rich maturin

    # Create activation helper script
    cat > "$SCRIPT_DIR/activate_env.sh" << 'ENVEOF'
#!/bin/bash
# Source this file to activate HURRICANE Python environment
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/.venv/bin/activate"
echo "HURRICANE Python environment activated"
ENVEOF
    chmod +x "$SCRIPT_DIR/activate_env.sh"

    echo -e "  ${GREEN}Python environment ready${NC}"
    echo -e "  ${CYAN}Tip: Run 'source activate_env.sh' to activate manually${NC}"
}

init_submodules() {
    echo -e "${BLUE}[5/7] Initializing git submodules (IPVNINER)...${NC}"
    if [ -f .gitmodules ]; then
        git submodule update --init --recursive
        echo -e "  ${GREEN}Submodules initialized${NC}"
    else
        echo -e "  ${YELLOW}No submodules configured${NC}"
    fi
}

build_fastport() {
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
}

install_scripts() {
    echo -e "${BLUE}[7/7] Installing HURRICANE scripts...${NC}"

    # Create wrapper scripts that activate venv
    sudo mkdir -p /usr/local/bin

    # Create hurricane wrapper
    sudo tee /usr/local/bin/hurricane > /dev/null << WRAPPER
#!/bin/bash
HURRICANE_DIR="$SCRIPT_DIR"
source "\$HURRICANE_DIR/.venv/bin/activate" 2>/dev/null || true
"\$HURRICANE_DIR/hurricane" "\$@"
WRAPPER
    sudo chmod +x /usr/local/bin/hurricane
    echo -e "  ${GREEN}Installed: hurricane${NC}"

    # Create TUI wrapper
    sudo tee /usr/local/bin/hurricane-tui > /dev/null << WRAPPER
#!/bin/bash
HURRICANE_DIR="$SCRIPT_DIR"
source "\$HURRICANE_DIR/.venv/bin/activate" 2>/dev/null || true
python3 "\$HURRICANE_DIR/hurricane_tui.py" "\$@"
WRAPPER
    sudo chmod +x /usr/local/bin/hurricane-tui
    echo -e "  ${GREEN}Installed: hurricane-tui${NC}"

    # Set execute permissions on local scripts
    chmod +x scripts/*.py 2>/dev/null || true
    chmod +x *.sh 2>/dev/null || true
    chmod +x hurricane 2>/dev/null || true
    chmod +x hurricane_tui.py 2>/dev/null || true
}

install_native() {
    print_banner
    echo -e "${CYAN}Starting Native Installation...${NC}"
    echo ""

    install_system_deps
    install_rust
    setup_python_venv
    init_submodules
    build_fastport
    install_scripts

    print_success_native
}

install_docker() {
    print_banner
    echo -e "${CYAN}Starting Docker Installation...${NC}"
    echo ""

    # Check for Docker
    echo -e "${BLUE}[1/4] Checking Docker installation...${NC}"
    if ! command -v docker &> /dev/null; then
        echo -e "  ${YELLOW}Docker not found. Installing...${NC}"
        curl -fsSL https://get.docker.com | sh
        sudo usermod -aG docker "$USER"
        echo -e "  ${GREEN}Docker installed. You may need to log out and back in.${NC}"
    else
        echo -e "  ${GREEN}Docker already installed${NC}"
    fi

    # Check for Docker Compose
    echo -e "${BLUE}[2/4] Checking Docker Compose...${NC}"
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        echo -e "  ${YELLOW}Installing Docker Compose plugin...${NC}"
        sudo apt-get install -y docker-compose-plugin 2>/dev/null || \
        sudo dnf install -y docker-compose-plugin 2>/dev/null || \
        pip3 install docker-compose
    fi
    echo -e "  ${GREEN}Docker Compose ready${NC}"

    # Verify Docker configuration files exist
    echo -e "${BLUE}[3/4] Checking Docker configuration...${NC}"
    if ! check_docker_files; then
        echo -e "${RED}Docker configuration files missing. Cannot proceed.${NC}"
        exit 1
    fi

    # Build and start
    echo -e "${BLUE}[4/4] Building Docker images...${NC}"
    docker compose build || docker-compose build

    print_success_docker
}

check_docker_files() {
    # Verify existing Docker files
    if [ ! -f "Dockerfile" ]; then
        echo -e "  ${RED}Dockerfile not found!${NC}"
        return 1
    fi
    if [ ! -f "docker-compose.yml" ]; then
        echo -e "  ${RED}docker-compose.yml not found!${NC}"
        return 1
    fi
    echo -e "  ${GREEN}Using existing Dockerfile and docker-compose.yml${NC}"
    return 0
}

update_deps_only() {
    print_banner
    echo -e "${CYAN}Updating dependencies...${NC}"
    echo ""

    # Update Python packages in venv
    if [ -d "$VENV_DIR" ]; then
        echo -e "${BLUE}Updating Python packages...${NC}"
        source "$VENV_DIR/bin/activate"
        pip install --upgrade pip Flask flask-cors requests aiohttp rich maturin
        echo -e "  ${GREEN}Python packages updated${NC}"
    else
        echo -e "${YELLOW}No virtual environment found. Run full installation first.${NC}"
    fi

    # Update Rust if available
    if command -v rustup &> /dev/null; then
        echo -e "${BLUE}Updating Rust toolchain...${NC}"
        rustup update
        echo -e "  ${GREEN}Rust updated${NC}"
    fi

    # Rebuild FASTPORT
    if [ -d "fastport/fastport-core" ]; then
        echo -e "${BLUE}Rebuilding FASTPORT...${NC}"
        source "$HOME/.cargo/env" 2>/dev/null || true
        cd fastport/fastport-core
        cargo build --release
        cd "$SCRIPT_DIR"
        echo -e "  ${GREEN}FASTPORT rebuilt${NC}"
    fi

    echo ""
    echo -e "${GREEN}Dependencies updated successfully!${NC}"
}

print_success_native() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║          Native Installation Complete!                    ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Quick Start:${NC}"
    echo -e "  ${BOLD}hurricane-tui${NC}          Launch interactive control center"
    echo -e "  ${BOLD}hurricane start${NC}        Start all services"
    echo -e "  ${BOLD}hurricane status${NC}       Check service status"
    echo ""
    echo -e "${CYAN}Configuration:${NC}"
    echo -e "  Tunnels:     ${YELLOW}config/tunnels/*.toml${NC}"
    echo -e "  Credentials: ${YELLOW}config/credentials/*.creds${NC}"
    echo ""
    echo -e "${CYAN}Access Points:${NC}"
    echo -e "  WebUI:       ${GREEN}http://127.0.0.1:8643${NC}"
    echo -e "  Daemon API:  ${BLUE}http://127.0.0.1:8642${NC}"
    echo ""
    echo -e "${CYAN}Python Environment:${NC}"
    echo -e "  Activate:    ${YELLOW}source activate_env.sh${NC}"
    echo -e "  Location:    ${YELLOW}$VENV_DIR${NC}"
    echo ""
}

print_success_docker() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║          Docker Installation Complete!                    ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Quick Start:${NC}"
    echo -e "  ${BOLD}docker compose up -d${NC}   Start containers"
    echo -e "  ${BOLD}docker compose down${NC}    Stop containers"
    echo -e "  ${BOLD}docker compose logs${NC}    View logs"
    echo ""
    echo -e "${CYAN}Access Points:${NC}"
    echo -e "  WebUI:       ${GREEN}http://127.0.0.1:8643${NC}"
    echo -e "  Daemon API:  ${BLUE}http://127.0.0.1:8642${NC}"
    echo ""
    echo -e "${YELLOW}Note: Run 'newgrp docker' or log out/in if docker commands fail${NC}"
    echo ""
}

# Main
main() {
    check_not_root
    detect_pkg_manager

    # Interactive TUI menu (no CLI flags - use menu selection)
    while true; do
        print_banner
        print_menu

        read -p "$(echo -e "${YELLOW}Enter choice [1-3, 0 to exit]: ${NC}")" choice

        case $choice in
            1)
                install_native
                exit 0
                ;;
            2)
                install_docker
                exit 0
                ;;
            3)
                update_deps_only
                read -p "Press Enter to continue..."
                ;;
            0)
                echo -e "\n${CYAN}Goodbye!${NC}\n"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid choice. Please select 0-3.${NC}"
                sleep 1
                ;;
        esac
    done
}

main "$@"
