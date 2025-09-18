#!/bin/bash

# WhatPulse PCap Service Uninstall Script

set -e

echo "WhatPulse PCap Service Uninstaller"
echo "=================================="

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    echo "Error: Do not run this script as root. It will request sudo when needed."
    exit 1
fi

echo "This will remove the WhatPulse PCap Service from your system."
read -p "Are you sure? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Uninstall cancelled."
    exit 0
fi

echo "Uninstalling WhatPulse PCap Service..."
sudo make uninstall

echo ""
echo "WhatPulse PCap Service has been successfully removed from your system."
