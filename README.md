# WhatPulse External PCap Service

A companion service that enables network monitoring for WhatPulse when running in AppImage or containerized environments on Linux.

## What it does

When WhatPulse runs as an AppImage or in other restricted environments, it may not have direct access to capture network packets. This service runs alongside WhatPulse to provide network monitoring capabilities by:

- Capturing network traffic using system-level access
- Filtering and processing packet data safely  
- Forwarding relevant statistics to WhatPulse via local connection

## Installation

### Package Manager Installation (Recommended)

Choose the package format for your Linux distribution:

#### Debian/Ubuntu (.deb)
```bash
wget https://releases.whatpulse.org/latest/external-pcap-service/whatpulse-pcap-service_1.0.0_amd64.deb
sudo dpkg -i whatpulse-pcap-service_1.0.0_amd64.deb
sudo apt-get install -f  # Fix any missing dependencies
```

#### Red Hat/Fedora/CentOS (.rpm)  
```bash
wget https://releases.whatpulse.org/latest/external-pcap-service/whatpulse-pcap-service-1.0.0-1.x86_64.rpm
sudo rpm -ivh whatpulse-pcap-service-1.0.0-1.x86_64.rpm
# OR on Fedora/newer systems:
sudo dnf install whatpulse-pcap-service-1.0.0-1.x86_64.rpm
```

#### Arch Linux (.pkg.tar.xz)
```bash
wget https://releases.whatpulse.org/latest/external-pcap-service/whatpulse-pcap-service-1.0.0-1-x86_64.pkg.tar.xz
sudo pacman -U whatpulse-pcap-service-1.0.0-1-x86_64.pkg.tar.xz
```

### Build from Source

If packages aren't available for your distribution:

```bash
# Download and extract source
wget https://releases.whatpulse.org/latest/external-pcap-service/whatpulse-pcap-service-1.0.0-source.tar.gz
tar xzf whatpulse-pcap-service-1.0.0-source.tar.gz
cd whatpulse-pcap-service-1.0.0

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

## Troubleshooting

### Check Service Status
```bash
# View service status
sudo systemctl status whatpulse-pcap-service

# View recent logs
sudo journalctl -u whatpulse-pcap-service -f
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
