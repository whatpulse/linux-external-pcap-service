#!/bin/bash

# WhatPulse PCap Service Installation Script
# This script builds and installs the WhatPulse PCap Service

set -e

echo "WhatPulse PCap Service Installer"
echo "==============================="

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    echo "Error: Do not run this script as root. It will request sudo when needed."
    exit 1
fi

# Check for required packages
echo "Checking dependencies..."
missing_packages=()

if ! command -v g++ >/dev/null 2>&1; then
    missing_packages+=("g++")
fi

if ! command -v make >/dev/null 2>&1; then
    missing_packages+=("make")
fi

if ! pkg-config --exists libpcap 2>/dev/null; then
    missing_packages+=("libpcap-dev")
fi

if [ ${#missing_packages[@]} -ne 0 ]; then
    echo "Missing required packages: ${missing_packages[*]}"
    echo "Please install them with your package manager, for example:"
    echo "  Ubuntu/Debian: sudo apt-get install build-essential libpcap-dev"
    echo "  CentOS/RHEL:   sudo yum install gcc-c++ make libpcap-devel"
    echo "  Fedora:        sudo dnf install gcc-c++ make libpcap-devel"
    echo "  Arch:          sudo pacman -S gcc make libpcap"
    exit 1
fi

# Build the service
echo "Building WhatPulse PCap Service..."
make clean
make

if [ ! -f "./whatpulse-pcap-service" ]; then
    echo "Error: Build failed. The executable was not created."
    exit 1
fi

echo "Build successful!"

# Test the executable
echo "Testing executable..."
if ! ./whatpulse-pcap-service --version >/dev/null 2>&1; then
    echo "Warning: The built executable may not work properly."
fi

# Install the service
echo "Installing service..."
sudo make install

echo ""
echo "Installation completed successfully!"
echo ""
echo "To start the service:"
echo "  sudo systemctl start whatpulse-pcap-service"
echo ""
echo "To enable auto-start at boot:"
echo "  sudo systemctl enable whatpulse-pcap-service"
echo ""
echo "To check service status:"
echo "  sudo systemctl status whatpulse-pcap-service"
echo ""
echo "To view logs:"
echo "  sudo journalctl -u whatpulse-pcap-service -f"
echo ""
echo "To manually run the service (for testing):"
echo "  sudo whatpulse-pcap-service --verbose"
echo ""
echo "Note: Make sure WhatPulse is running and listening on port 3499"
echo "      before starting this service."
