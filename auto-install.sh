#!/bin/bash
#
# WhatPulse PCap Service Auto-Installer
# ======================================
#
# This script automatically detects your Linux distribution and installs
# the appropriate package for the WhatPulse External PCap Service.
#
# Usage:
#   curl -fsSL https://whatpulse.org/linux/auto-install.sh | bash
#   or
#   wget -qO- https://whatpulse.org/linux/auto-install.sh | bash
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# GitHub repository information
GITHUB_REPO="whatpulse/linux-external-pcap-service"
PACKAGE_NAME="whatpulse-pcap-service"

# Print colored output
print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_header() {
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  WhatPulse PCap Service - Auto Installer${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}\n"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Detect the Linux distribution
detect_distro() {
    print_info "Detecting Linux distribution..."

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        DISTRO_LIKE=$ID_LIKE
        VERSION_ID=$VERSION_ID
        print_success "Detected: $PRETTY_NAME"
    elif [ -f /etc/lsb-release ]; then
        . /etc/lsb-release
        DISTRO=$DISTRIB_ID
        print_success "Detected: $DISTRIB_DESCRIPTION"
    else
        print_error "Unable to detect Linux distribution"
        print_info "Please install manually using the instructions at:"
        print_info "https://github.com/$GITHUB_REPO"
        exit 1
    fi
}

# Determine package type based on distro
determine_package_type() {
    case "$DISTRO" in
        ubuntu|debian|linuxmint|pop|elementary|zorin)
            PACKAGE_TYPE="deb"
            PACKAGE_EXT="deb"
            ;;
        fedora|rhel|centos|rocky|almalinux|oracle)
            PACKAGE_TYPE="rpm"
            PACKAGE_EXT="rpm"
            ;;
        arch|manjaro|endeavouros|garuda)
            PACKAGE_TYPE="arch"
            PACKAGE_EXT="pkg.tar.zst"
            ;;
        *)
            # Check distro-like for derived distributions
            case "$DISTRO_LIKE" in
                *debian*|*ubuntu*)
                    PACKAGE_TYPE="deb"
                    PACKAGE_EXT="deb"
                    ;;
                *rhel*|*fedora*)
                    PACKAGE_TYPE="rpm"
                    PACKAGE_EXT="rpm"
                    ;;
                *arch*)
                    PACKAGE_TYPE="arch"
                    PACKAGE_EXT="pkg.tar.zst"
                    ;;
                *)
                    PACKAGE_TYPE="unsupported"
                    ;;
            esac
            ;;
    esac

    if [ "$PACKAGE_TYPE" = "unsupported" ]; then
        print_error "No pre-built package available for your distribution: $DISTRO"
        echo ""
        print_info "You can build from source instead:"
        echo ""
        echo "  # Install dependencies (adjust for your package manager):"
        echo "  sudo apt-get install build-essential libpcap-dev  # Debian/Ubuntu"
        echo "  sudo yum install gcc-c++ libpcap-devel           # RHEL/CentOS"
        echo "  sudo dnf install gcc-c++ libpcap-devel           # Fedora"
        echo "  sudo pacman -S base-devel libpcap                # Arch"
        echo ""
        echo "  # Download and build:"
        echo "  wget https://github.com/$GITHUB_REPO/releases/latest/download/$PACKAGE_NAME-VERSION-source.tar.gz"
        echo "  tar xzf $PACKAGE_NAME-*-source.tar.gz"
        echo "  cd $PACKAGE_NAME-*"
        echo "  make"
        echo "  sudo make install"
        echo ""
        print_info "For more details, see: https://github.com/$GITHUB_REPO/blob/main/README.md"
        exit 1
    fi

    print_success "Package type: $PACKAGE_TYPE"
}

# Check for required commands
check_dependencies() {
    local missing_deps=()

    if ! command -v curl >/dev/null 2>&1; then
        missing_deps+=("curl")
    fi

    if ! command -v jq >/dev/null 2>&1; then
        print_warning "jq not found, will use fallback method for JSON parsing"
    fi

    if [ ${#missing_deps[@]} -gt 0 ]; then
        print_error "Missing required dependencies: ${missing_deps[*]}"
        print_info "Please install them and try again"
        exit 1
    fi
}

# Get latest release information from GitHub
get_latest_release() {
    print_info "Fetching latest release information..."

    local api_url="https://api.github.com/repos/$GITHUB_REPO/releases/latest"
    local response

    response=$(curl -fsSL "$api_url" 2>/dev/null)

    if [ $? -ne 0 ]; then
        print_error "Failed to fetch release information from GitHub"
        exit 1
    fi

    # Extract version and download URL
    if command -v jq >/dev/null 2>&1; then
        VERSION=$(echo "$response" | jq -r '.tag_name' | sed 's/^v//')

        case "$PACKAGE_TYPE" in
            deb)
                DOWNLOAD_URL=$(echo "$response" | jq -r '.assets[] | select(.name | endswith(".deb")) | .browser_download_url')
                ;;
            rpm)
                DOWNLOAD_URL=$(echo "$response" | jq -r '.assets[] | select(.name | endswith(".rpm")) | .browser_download_url')
                ;;
            arch)
                DOWNLOAD_URL=$(echo "$response" | jq -r '.assets[] | select(.name | contains(".pkg.tar.")) | .browser_download_url')
                ;;
        esac
    else
        # Fallback parsing without jq
        VERSION=$(echo "$response" | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4 | sed 's/^v//')

        case "$PACKAGE_TYPE" in
            deb)
                DOWNLOAD_URL=$(echo "$response" | grep -o '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]*\.deb"' | head -1 | cut -d'"' -f4)
                ;;
            rpm)
                DOWNLOAD_URL=$(echo "$response" | grep -o '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]*\.rpm"' | head -1 | cut -d'"' -f4)
                ;;
            arch)
                DOWNLOAD_URL=$(echo "$response" | grep -o '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]*\.pkg\.tar\.[^"]*"' | head -1 | cut -d'"' -f4)
                ;;
        esac
    fi

    if [ -z "$VERSION" ] || [ -z "$DOWNLOAD_URL" ]; then
        print_error "Failed to parse release information"
        exit 1
    fi

    print_success "Latest version: $VERSION"
}

# Download the package
download_package() {
    print_info "Downloading package..."

    TEMP_DIR=$(mktemp -d)
    PACKAGE_FILE="$TEMP_DIR/$(basename "$DOWNLOAD_URL")"

    if ! curl -fsSL -o "$PACKAGE_FILE" "$DOWNLOAD_URL"; then
        print_error "Failed to download package"
        rm -rf "$TEMP_DIR"
        exit 1
    fi

    print_success "Package downloaded to $PACKAGE_FILE"
}

# Install the package
install_package() {
    print_info "Installing package..."

    case "$PACKAGE_TYPE" in
        deb)
            if ! dpkg -i "$PACKAGE_FILE" 2>/dev/null; then
                print_warning "Installing missing dependencies..."
                apt-get update -qq
                apt-get install -f -y
            fi
            ;;
        rpm)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y "$PACKAGE_FILE"
            elif command -v yum >/dev/null 2>&1; then
                yum install -y "$PACKAGE_FILE"
            else
                rpm -ivh "$PACKAGE_FILE"
            fi
            ;;
        arch)
            pacman -U --noconfirm "$PACKAGE_FILE"
            ;;
    esac

    if [ $? -eq 0 ]; then
        print_success "Package installed successfully"
    else
        print_error "Package installation failed"
        rm -rf "$TEMP_DIR"
        exit 1
    fi
}

# Clean up temporary files
cleanup() {
    if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
        print_info "Cleaned up temporary files"
    fi
}

# Start and enable the service
setup_service() {
    print_info "Setting up systemd service..."

    systemctl daemon-reload

    if systemctl is-active --quiet "$PACKAGE_NAME"; then
        print_info "Service is already running, restarting..."
        systemctl restart "$PACKAGE_NAME"
    else
        systemctl start "$PACKAGE_NAME"
    fi

    if systemctl is-enabled --quiet "$PACKAGE_NAME"; then
        print_info "Service is already enabled for automatic startup"
    else
        systemctl enable "$PACKAGE_NAME"
        print_success "Service enabled for automatic startup"
    fi

    # Check service status
    if systemctl is-active --quiet "$PACKAGE_NAME"; then
        print_success "Service is running"
    else
        print_warning "Service failed to start. Check status with: sudo systemctl status $PACKAGE_NAME"
    fi
}

# Print final instructions
print_final_instructions() {
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  Installation Complete!${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo ""
    echo "WhatPulse PCap Service v$VERSION has been installed and started."
    echo ""
    echo "Useful commands:"
    echo "  • Check status:  sudo systemctl status $PACKAGE_NAME"
    echo "  • View logs:     sudo tail -f /var/log/whatpulse-pcap.log"
    echo "  • Stop service:  sudo systemctl stop $PACKAGE_NAME"
    echo "  • Start service: sudo systemctl start $PACKAGE_NAME"
    echo "  • Restart:       sudo systemctl restart $PACKAGE_NAME"
    echo ""
    echo "The service will automatically start on system boot."
    echo ""
    print_info "For support and documentation, visit:"
    print_info "https://github.com/$GITHUB_REPO"
    echo ""
}

# Main installation flow
main() {
    print_header

    check_root
    detect_distro
    determine_package_type
    check_dependencies
    get_latest_release
    download_package
    install_package
    cleanup
    setup_service
    print_final_instructions
}

# Trap errors and cleanup
trap cleanup EXIT

# Run main function
main
