# WhatPulse External PCap Service

A companion service that enables network monitoring for WhatPulse when running in AppImage or containerized environments on Linux.

## What it does

When WhatPulse runs as an AppImage or in other restricted environments, it may not have direct access to capture network packets. This service runs alongside WhatPulse to provide network monitoring capabilities by:

- Capturing network traffic using high-performance PF_RING or traditional PCap
- Filtering and processing packet data safely
- Forwarding relevant statistics to WhatPulse via local connection

## Installation

### Quick Install (Recommended)

The easiest way to install is using our auto-installer script, which detects your distribution and installs the appropriate package:

```bash
curl -fsSL https://raw.githubusercontent.com/whatpulse/linux-external-pcap-service/main/auto-install.sh | sudo bash
```

Or using wget:
```bash
wget -qO- https://raw.githubusercontent.com/whatpulse/linux-external-pcap-service/main/auto-install.sh | sudo bash
```

This script will:
- Detect your Linux distribution
- Download the latest release package
- Install it using your package manager
- Start and enable the systemd service

### Manual Package Installation

Download the latest packages from the [GitHub Releases page](https://github.com/whatpulse/linux-external-pcap-service).

Choose the package format for your Linux distribution:

#### Debian/Ubuntu (.deb)
```bash
# Download from releases page, then:
sudo dpkg -i whatpulse-pcap-service_*_amd64.deb
sudo apt-get install -f  # Fix any missing dependencies
```

#### Red Hat/Fedora/CentOS (.rpm)
```bash
# Download from releases page, then:
sudo rpm -ivh whatpulse-pcap-service-*-1.x86_64.rpm
# OR on Fedora/newer systems:
sudo dnf install whatpulse-pcap-service-*-1.x86_64.rpm
```

#### Arch Linux (.pkg.tar.*)
```bash
# Download from releases page, then:
sudo pacman -U whatpulse-pcap-service-*-1-x86_64.pkg.tar.*
```

### Quick Download Commands

For automated downloads, use these commands to get the latest release:

```bash
# Get latest release info
LATEST_URL=$(curl -s https://api.github.com/repos/whatpulse/linux-external-pcap-service/releases/latest | grep "browser_download_url" | grep "deb" | cut -d '"' -f 4)
wget "$LATEST_URL"

# Or browse all releases:
# https://github.com/whatpulse/linux-external-pcap-service/releases
```

### Build from Source

If packages aren't available for your distribution, or you prefer to build from source:

```bash
# Download and extract source from GitHub releases
# Visit: https://github.com/whatpulse/linux-external-pcap-service/releases
# Download: whatpulse-pcap-service-VERSION-source.tar.gz

tar xzf whatpulse-pcap-service-*-source.tar.gz
cd whatpulse-pcap-service-*

# Install build dependencies
# Debian/Ubuntu:
sudo apt-get install build-essential libpcap-dev

# Red Hat/Fedora/CentOS:
sudo yum install gcc-c++ libpcap-devel  # or: sudo dnf install gcc-c++ libpcap-devel

# Arch Linux:
sudo pacman -S base-devel libpcap

# Build and install
make
sudo make install
```

## Installation Paths

The service uses different paths depending on the installation method:

- **Package installations** (deb, rpm, etc.): Binary at `/usr/bin/whatpulse-pcap-service`
- **Manual installations** (make install, install.sh): Binary at `/usr/local/bin/whatpulse-pcap-service`

Both use the same systemd service name: `whatpulse-pcap-service`

The appropriate systemd service file is automatically selected during installation.

## Usage

### Starting the Service

After installation, start the service:

```bash
# Start the service
sudo systemctl start whatpulse-pcap-service

# Enable automatic startup at boot
sudo systemctl enable whatpulse-pcap-service

# Check if it's running
sudo systemctl status whatpulse-pcap-service
```

### Configuring WhatPulse

The service will automatically connect to WhatPulse when both are running. No additional WhatPulse configuration is needed in most cases.

## Upgrading

### Package Manager Upgrade

If you installed via package manager, upgrading is straightforward:

#### Debian/Ubuntu
```bash
# Download the new .deb package from releases, then:
sudo dpkg -i whatpulse-pcap-service_*_amd64.deb
sudo apt-get install -f  # Fix any dependencies if needed

# Or if added to a repository:
sudo apt-get update && sudo apt-get upgrade whatpulse-pcap-service
```

#### Red Hat/Fedora/CentOS
```bash
# Download the new .rpm package from releases, then:
sudo rpm -Uvh whatpulse-pcap-service-*-1.x86_64.rpm
# OR on Fedora/newer systems:
sudo dnf upgrade whatpulse-pcap-service-*-1.x86_64.rpm
```

#### Arch Linux
```bash
# Download the new package from releases, then:
sudo pacman -U whatpulse-pcap-service-*-1-x86_64.pkg.tar.*
```

### Manual/Source Upgrade

For manual installations, follow these steps:

```bash
# Stop the service
sudo systemctl stop whatpulse-pcap-service

# Download and extract the new source
tar xzf whatpulse-pcap-service-*-source.tar.gz
cd whatpulse-pcap-service-*

# Build and install
make
sudo make install

# Restart the service
sudo systemctl start whatpulse-pcap-service

# Verify the upgrade
sudo systemctl status whatpulse-pcap-service
```

### Checking Version

To verify which version is currently installed:

```bash
# Check the service version
whatpulse-pcap-service --version

# Or check systemd service status
sudo systemctl status whatpulse-pcap-service
```

**Note:** The service may need to be restarted after upgrading to ensure the new version is running. Package manager installations typically handle this automatically, but manual installations may require a manual restart.

## Troubleshooting

### Check Service Status
```bash
# View service status
sudo systemctl status whatpulse-pcap-service

# View recent logs
sudo tail /var/log/whatpulse-pcap.log
```

### Common Issues

- **Service won't start**: Ensure you have root/admin privileges and libpcap is installed
- **WhatPulse not receiving data**: Check that both WhatPulse and the service are running
- **Permission errors**: The service needs root privileges to capture network packets

### Manual Testing

For troubleshooting, you can run the service manually:

```bash
sudo whatpulse-pcap-service --verbose
```

## Uninstallation

### Package Manager
```bash
# Debian/Ubuntu
sudo apt-get remove whatpulse-pcap-service

# Red Hat/Fedora/CentOS
sudo rpm -e whatpulse-pcap-service

# Arch Linux
sudo pacman -R whatpulse-pcap-service
```

### Manual/Source Installation
```bash
sudo systemctl stop whatpulse-pcap-service
sudo systemctl disable whatpulse-pcap-service
sudo rm /etc/systemd/system/whatpulse-pcap-service.service
sudo rm /usr/local/bin/whatpulse-pcap-service
sudo systemctl daemon-reload
```

## Support

For issues or questions about this service, please refer to the main WhatPulse support channels or documentation.

## License

This software is licensed under **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)** with additional terms specific to WhatPulse integration.

See the [LICENSE](LICENSE) file for complete terms and conditions.

**Key permissions:**
- ✅ Personal and educational use
- ✅ Modification and redistribution (with attribution)
- ✅ Open source contributions

**Key restrictions:**
- ❌ Commercial use or resale
- ❌ Reverse engineering WhatPulse communication protocol
- ❌ Tampering with data transmission
- ❌ Protocol circumvention or data injection

For commercial licensing inquiries: support@whatpulse.org


## Release Process

Releases are automated via GitHub Actions. Follow these steps to create a new release:

**Update version:**
```bash
# Edit main.cpp
# Change PCAP_SERVICE_VERSION to your new version (e.g., "1.0.1")
```

**Commit and push changes:**
```bash
git add main.cpp
git commit -m "bump version to 1.0.1"
git push origin master
```

**Create and push version tag:**
```bash
git tag v1.0.1
git push origin v1.0.1
```