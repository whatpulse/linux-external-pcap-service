# Packaging Scripts

This directory contains self-contained packaging scripts for the WhatPulse External PCap Service.

## Scripts

### `build-deb.sh`
Creates Debian/Ubuntu packages (`.deb` files).

**Usage:**
```bash
./scripts/build-deb.sh 1.0.1
```

**Requirements:**
- `dpkg-dev`
- `debhelper`

**Output:** `dist/whatpulse-pcap-service_VERSION_amd64.deb`

### `build-rpm.sh`
Creates RedHat/CentOS/Fedora packages (`.rpm` files).

**Usage:**
```bash
./scripts/build-rpm.sh 1.0.1
```

**Requirements:**
- `rpm-build`
- `rpmbuild`

**Output:** `dist/whatpulse-pcap-service-VERSION-1.x86_64.rpm`

### `build-arch.sh`
Creates Arch Linux packages (`.pkg.tar.gz` files).

**Usage:**
```bash
./scripts/build-arch.sh 1.0.1
```

**Requirements:**
- `makepkg` (native Arch Linux) **OR**
- `docker` (Ubuntu/other distros - uses Arch container)

**Output:** `dist/whatpulse-pcap-service-VERSION-1-x86_64.pkg.tar.xz`

**Note:** On GitHub Actions (Ubuntu runners), this automatically uses Docker with an official Arch Linux container to build native packages.

## Prerequisites

Before running any packaging script:

1. **Build the binary:**
   ```bash
   make clean && make shared
   ```

2. **Ensure required files exist:**
   - `whatpulse-pcap-service` (binary)
   - `whatpulse-pcap-service.service` (systemd service file)
   - `README.md`
   - `LICENSE`

## Package Features

All packages include:

- **Binary installation:** `/usr/bin/whatpulse-pcap-service`
- **Systemd service:** `/etc/systemd/system/whatpulse-pcap-service.service` (or `/usr/lib/systemd/system/`)
- **Documentation:** `/usr/share/doc/whatpulse-pcap-service/`
- **Post-install scripts:** Automatically reload systemd and enable service
- **Pre-remove scripts:** Stop and disable service before removal

## Manual Testing

To test a package locally:

```bash
# Build the service
make clean && make shared

# Create package
./scripts/build-deb.sh 1.0.0-test

# Install (test environment only!)
sudo dpkg -i dist/whatpulse-pcap-service_1.0.0-test_amd64.deb

# Test service
sudo systemctl status whatpulse-pcap-service
sudo systemctl start whatpulse-pcap-service

# Remove
sudo dpkg -r whatpulse-pcap-service
```

## GitHub Actions Integration

These scripts are automatically called by the GitHub Actions workflow (`.github/workflows/external-pcap-service.yml`) when:

- A version tag (`v*`) is pushed
- The workflow is manually triggered

The workflow handles dependency installation and artifact collection automatically.
