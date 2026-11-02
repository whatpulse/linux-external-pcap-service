#!/bin/bash
#
# WhatPulse PCap Service Auto-Installer
# ======================================
#
# This script automatically detects your Linux distribution and installs
# the appropriate package for the WhatPulse External PCap Service.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/whatpulse/linux-external-pcap-service/main/auto-install.sh | sudo bash
#   or
#   wget -qO- https://raw.githubusercontent.com/whatpulse/linux-external-pcap-service/main/auto-install.sh | sudo bash
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
        print_success "Detected: $PRETTY_NAME"
    elif [ -f /etc/lsb-release ]; then
        . /etc/lsb-release
        DISTRO=$(echo "$DISTRIB_ID" | tr '[:upper:]' '[:lower:]')
        print_success "Detected: $DISTRIB_DESCRIPTION"
    else
        print_error "Unable to detect Linux distribution"
        print_info "Please install manually using the instructions at:"
        print_info "https://github.com/$GITHUB_REPO"
        exit 1
    fi
}

# Explain how to build from source when no pre-built package fits this system
print_source_build_instructions() {
    print_info "You can build from source instead:"
    echo ""
    echo "  # Install dependencies (adjust for your package manager):"
    echo "  sudo apt-get install build-essential libpcap-dev  # Debian/Ubuntu"
    echo "  sudo dnf install gcc-c++ make libpcap-devel       # Fedora/RHEL"
    echo "  sudo zypper install gcc-c++ make libpcap-devel    # openSUSE"
    echo "  sudo pacman -S base-devel libpcap                 # Arch"
    echo ""
    echo "  # Download and build:"
    echo "  wget https://github.com/$GITHUB_REPO/releases/latest/download/$PACKAGE_NAME-VERSION-source.tar.gz"
    echo "  tar xzf $PACKAGE_NAME-*-source.tar.gz"
    echo "  cd $PACKAGE_NAME-*"
    echo "  make"
    echo "  sudo make install"
    echo ""
    print_info "For more details, see: https://github.com/$GITHUB_REPO/blob/main/README.md"
}

# Pre-built packages are x86_64 only
check_architecture() {
    local arch
    arch=$(uname -m)

    if [ "$arch" != "x86_64" ]; then
        print_error "No pre-built package available for your architecture: $arch"
        echo ""
        print_source_build_instructions
        exit 1
    fi
}

# Determine package type based on distro
determine_package_type() {
    case "$DISTRO" in
        ubuntu|debian|linuxmint|pop|elementary|zorin)
            PACKAGE_TYPE="deb"
            ;;
        fedora|rhel|centos|rocky|almalinux|ol|amzn|opensuse*|sles|sled)
            PACKAGE_TYPE="rpm"
            ;;
        arch|manjaro|endeavouros|garuda)
            PACKAGE_TYPE="arch"
            ;;
        *)
            # Check distro-like for derived distributions
            case "$DISTRO_LIKE" in
                *debian*|*ubuntu*)
                    PACKAGE_TYPE="deb"
                    ;;
                *rhel*|*fedora*|*centos*|*suse*)
                    PACKAGE_TYPE="rpm"
                    ;;
                *arch*)
                    PACKAGE_TYPE="arch"
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
        print_source_build_instructions
        exit 1
    fi

    print_success "Package type: $PACKAGE_TYPE"
}

# Check for required commands
check_dependencies() {
    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
        print_error "Missing required dependency: curl or wget"
        print_info "Please install one of them and try again"
        exit 1
    fi
}

# Download a URL to a file, or to stdout when no file is given
fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "${2:--}" "$1"
    else
        wget -qO "${2:--}" "$1"
    fi
}

# Check if the package is already installed and get its version
check_installed_version() {
    INSTALLED_VERSION=""

    case "$PACKAGE_TYPE" in
        deb)
            if dpkg -s "$PACKAGE_NAME" >/dev/null 2>&1; then
                INSTALLED_VERSION=$(dpkg -s "$PACKAGE_NAME" 2>/dev/null | grep '^Version:' | awk '{print $2}')
            fi
            ;;
        rpm)
            if rpm -q "$PACKAGE_NAME" >/dev/null 2>&1; then
                INSTALLED_VERSION=$(rpm -q --queryformat '%{VERSION}' "$PACKAGE_NAME" 2>/dev/null)
            fi
            ;;
        arch)
            if pacman -Q "$PACKAGE_NAME" >/dev/null 2>&1; then
                INSTALLED_VERSION=$(pacman -Q "$PACKAGE_NAME" 2>/dev/null | awk '{print $2}' | sed 's/-.*//')
            fi
            ;;
    esac

    if [ -n "$INSTALLED_VERSION" ]; then
        print_info "Currently installed version: $INSTALLED_VERSION"
    else
        print_info "No existing installation found"
    fi
}

# Get latest release information from GitHub
get_latest_release() {
    print_info "Fetching latest release information..."

    local api_url="https://api.github.com/repos/$GITHUB_REPO/releases/latest"
    local response
    local asset_pattern

    if ! response=$(fetch "$api_url" 2>/dev/null); then
        print_error "Failed to fetch release information from GitHub"
        print_info "Check your connection, or try again later if GitHub's API rate limit was reached"
        exit 1
    fi

    case "$PACKAGE_TYPE" in
        deb)  asset_pattern='\.deb$' ;;
        rpm)  asset_pattern='\.rpm$' ;;
        arch) asset_pattern='\.pkg\.tar\.[a-z0-9]+$' ;;
    esac

    # Parsed with grep so that this doesn't depend on jq being installed
    VERSION=$(echo "$response" | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4 | sed 's/^v//')
    DOWNLOAD_URL=$(echo "$response" | grep -o '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4 | grep -E "$asset_pattern" | grep -v 'debug' | head -n 1)

    if [ -z "$VERSION" ] || [ -z "$DOWNLOAD_URL" ]; then
        print_error "Failed to parse release information"
        exit 1
    fi

    print_success "Latest version: $VERSION"

    # Compare with installed version
    if [ -n "$INSTALLED_VERSION" ]; then
        if [ "$INSTALLED_VERSION" = "$VERSION" ]; then
            print_success "Already running the latest version ($VERSION)"
            cleanup
            exit 0
        else
            INSTALL_MODE="upgrade"
            print_info "Upgrading from $INSTALLED_VERSION to $VERSION"
        fi
    else
        INSTALL_MODE="install"
    fi
}

# Download the package
download_package() {
    print_info "Downloading package..."

    TEMP_DIR=$(mktemp -d)
    PACKAGE_FILE="$TEMP_DIR/$(basename "$DOWNLOAD_URL")"

    if ! fetch "$DOWNLOAD_URL" "$PACKAGE_FILE"; then
        print_error "Failed to download package"
        rm -rf "$TEMP_DIR"
        exit 1
    fi

    print_success "Package downloaded to $PACKAGE_FILE"
}

# Install the package with the system's package manager, which resolves dependencies
run_package_manager() {
    case "$PACKAGE_TYPE" in
        deb)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq || print_warning "Could not refresh package lists, continuing anyway"
            apt-get install -y "$PACKAGE_FILE"
            ;;
        rpm)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y "$PACKAGE_FILE"
            elif command -v yum >/dev/null 2>&1; then
                yum install -y "$PACKAGE_FILE"
            elif command -v zypper >/dev/null 2>&1; then
                zypper --non-interactive install --allow-unsigned-rpm "$PACKAGE_FILE"
            else
                rpm -Uvh "$PACKAGE_FILE"
            fi
            ;;
        arch)
            pacman -U --noconfirm "$PACKAGE_FILE"
            ;;
    esac
}

install_package() {
    print_info "Installing package..."

    if run_package_manager; then
        print_success "Package installed successfully"
    else
        print_error "Package installation failed"
        exit 1
    fi
}

# A package can install fine and still not run, e.g. when the system's glibc is too old
verify_binary() {
    local output

    if ! output=$("$PACKAGE_NAME" --version 2>&1); then
        print_error "The installed service cannot run on this system:"
        echo "$output"
        echo ""
        print_source_build_instructions
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
    SERVICE_RUNNING=false

    if [ ! -d /run/systemd/system ]; then
        print_warning "systemd is not running, so the service was not started"
        print_info "Start it manually with: sudo $PACKAGE_NAME"
        return
    fi

    print_info "Setting up systemd service..."

    systemctl daemon-reload || true

    if systemctl is-active --quiet "$PACKAGE_NAME"; then
        print_info "Service is already running, restarting..."
        systemctl restart "$PACKAGE_NAME" || true
    else
        systemctl start "$PACKAGE_NAME" || true
    fi

    if systemctl is-enabled --quiet "$PACKAGE_NAME"; then
        print_info "Service is already enabled for automatic startup"
    elif systemctl enable "$PACKAGE_NAME"; then
        print_success "Service enabled for automatic startup"
    else
        print_warning "Could not enable the service for automatic startup"
    fi

    # Give the service a moment: it counts as active right after starting, even if it then exits
    sleep 2

    # Check service status
    if systemctl is-active --quiet "$PACKAGE_NAME"; then
        SERVICE_RUNNING=true
        print_success "Service is running"
    else
        print_warning "Service failed to start. Check why with: sudo journalctl -u $PACKAGE_NAME -n 50"
    fi
}

# Print final instructions
print_final_instructions() {
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    if [ "$INSTALL_MODE" = "upgrade" ]; then
        echo -e "${GREEN}  Upgrade Complete!${NC}"
    else
        echo -e "${GREEN}  Installation Complete!${NC}"
    fi
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo ""
    if [ "$INSTALL_MODE" = "upgrade" ]; then
        echo "WhatPulse PCap Service upgraded from $INSTALLED_VERSION to $VERSION."
    elif [ "$SERVICE_RUNNING" = "true" ]; then
        echo "WhatPulse PCap Service v$VERSION has been installed and started."
    else
        echo "WhatPulse PCap Service v$VERSION has been installed, but is not running."
    fi
    echo ""
    echo "Useful commands:"
    echo "  • Check status:  sudo systemctl status $PACKAGE_NAME"
    echo "  • View logs:     sudo journalctl -u $PACKAGE_NAME -f"
    echo "  • Stop service:  sudo systemctl stop $PACKAGE_NAME"
    echo "  • Start service: sudo systemctl start $PACKAGE_NAME"
    echo "  • Restart:       sudo systemctl restart $PACKAGE_NAME"
    echo ""
    if [ "$SERVICE_RUNNING" = "true" ]; then
        echo "The service will automatically start on system boot."
        echo ""
    fi
    print_info "For support and documentation, visit:"
    print_info "https://github.com/$GITHUB_REPO"
    echo ""
}

# Main installation flow
main() {
    print_header

    check_root
    check_architecture
    detect_distro
    determine_package_type
    check_dependencies
    check_installed_version
    get_latest_release
    download_package
    install_package
    verify_binary
    cleanup
    setup_service
    print_final_instructions
}

# Trap errors and cleanup
trap cleanup EXIT

# Run main function
main
