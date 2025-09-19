#!/bin/bash
set -e

VERSION=${1:-1.0.0}
PACKAGE_NAME="whatpulse-pcap-service"
BUILD_DIR="scripts/arch/build"

echo "Building Arch Linux package for version $VERSION"

# Clean and create build directory
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Check if we're on Arch Linux with makepkg available, or use Docker
if command -v makepkg >/dev/null 2>&1; then
    echo "Using native makepkg"

    # Create PKGBUILD
    cat > "$BUILD_DIR/PKGBUILD" << EOF
# Maintainer: WhatPulse <support@whatpulse.org>
pkgname=$PACKAGE_NAME
pkgver=$VERSION
pkgrel=1
pkgdesc="External PCap service for WhatPulse network monitoring"
arch=('x86_64')
url="https://whatpulse.org"
license=('custom')
depends=('libpcap' 'systemd')
source=("\$pkgname" "\$pkgname.service")
sha256sums=('SKIP' 'SKIP')

package() {
    install -Dm755 "\$pkgname" "\$pkgdir/usr/bin/\$pkgname"
    install -Dm644 "\$pkgname.service" "\$pkgdir/usr/lib/systemd/system/\$pkgname.service"
}
EOF

    # Copy source files
    cp "$PACKAGE_NAME" "$BUILD_DIR/"
    cp "${PACKAGE_NAME}.service" "$BUILD_DIR/"

    # Build the package
    cd "$BUILD_DIR"
    makepkg -f

    # Move to dist directory
    cd ../../..
    mkdir -p dist
    find "$BUILD_DIR" -name "*.pkg.tar.*" -exec cp {} dist/ \;

    echo "Arch package created in dist/ directory"
elif command -v docker >/dev/null 2>&1; then
    echo "Using Docker with Arch Linux container for native makepkg build"

    # Create PKGBUILD for Docker build
    cat > "$BUILD_DIR/PKGBUILD" << EOF
# Maintainer: WhatPulse <support@whatpulse.org>
pkgname=$PACKAGE_NAME
pkgver=$VERSION
pkgrel=1
pkgdesc="External PCap service for WhatPulse network monitoring"
arch=('x86_64')
url="https://whatpulse.org"
license=('custom')
depends=('libpcap' 'systemd')
source=("\$pkgname" "\$pkgname.service")
sha256sums=('SKIP' 'SKIP')

package() {
    install -Dm755 "\$pkgname" "\$pkgdir/usr/bin/\$pkgname"
    install -Dm644 "\$pkgname.service" "\$pkgdir/usr/lib/systemd/system/\$pkgname.service"
}
EOF

    # Copy source files to build directory
    cp "$PACKAGE_NAME" "$BUILD_DIR/"
    cp "${PACKAGE_NAME}.service" "$BUILD_DIR/"

    # Use official Arch Linux Docker image to build the package
    docker run --rm -v "$(pwd)/$BUILD_DIR:/build" -w /build \
        archlinux:latest \
        bash -c "
            pacman -Syu --noconfirm base-devel libpcap systemd &&
            useradd -m builduser &&
            chown -R builduser:builduser /build &&
            sudo -u builduser makepkg -f --noconfirm
        "

    # Move to dist directory
    mkdir -p dist
    find "$BUILD_DIR" -name "*.pkg.tar.*" -exec cp {} dist/ \;

    echo "Arch package created using Docker in dist/ directory"
else
    echo "makepkg not available, creating tar-based package instead"

    # Create a simple tar-based package for Arch systems without makepkg
    mkdir -p "$BUILD_DIR/pkg/usr/bin"
    mkdir -p "$BUILD_DIR/pkg/usr/lib/systemd/system"

    # Copy files
    cp "$PACKAGE_NAME" "$BUILD_DIR/pkg/usr/bin/"
    cp "${PACKAGE_NAME}.service" "$BUILD_DIR/pkg/usr/lib/systemd/system/"

    # Create install script
    cat > "$BUILD_DIR/pkg/.INSTALL" << 'EOF'
#!/bin/bash
# Post-install script for whatpulse-pcap-service

post_install() {
    systemctl daemon-reload
    echo "WhatPulse PCap Service installed successfully."
    echo "To enable and start the service, run:"
    echo "  sudo systemctl enable --now whatpulse-pcap-service"
}

pre_remove() {
    systemctl stop whatpulse-pcap-service 2>/dev/null || true
    systemctl disable whatpulse-pcap-service 2>/dev/null || true
}

post_remove() {
    systemctl daemon-reload
}

case "$1" in
    install)
        post_install
        ;;
    remove)
        pre_remove
        ;;
    purge)
        post_remove
        ;;
esac
EOF

    # Create package info
    cat > "$BUILD_DIR/pkg/.PKGINFO" << EOF
pkgname = $PACKAGE_NAME
pkgver = $VERSION-1
pkgdesc = External PCap service for WhatPulse network monitoring
url = https://whatpulse.org
arch = x86_64
license = custom
depend = libpcap
depend = systemd
EOF

    # Create the package
    cd "$BUILD_DIR/pkg"
    tar -czf "../${PACKAGE_NAME}-${VERSION}-1-x86_64.pkg.tar.gz" *

    cd ../../..
    mkdir -p dist
    mv "$BUILD_DIR/${PACKAGE_NAME}-${VERSION}-1-x86_64.pkg.tar.gz" dist/

    echo "Arch-style package created in dist/ directory"
fi
