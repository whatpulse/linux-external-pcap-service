#!/bin/bash
set -e

VERSION=${1:-1.0.0}
PACKAGE_NAME="whatpulse-pcap-service"
BUILD_DIR="scripts/deb/build"
PACKAGE_DIR="$BUILD_DIR/${PACKAGE_NAME}_${VERSION}_amd64"

echo "Building Debian package for version $VERSION"

# Clean and create build directory
rm -rf "$BUILD_DIR"
mkdir -p "$PACKAGE_DIR"

# Create directory structure
mkdir -p "$PACKAGE_DIR/DEBIAN"
mkdir -p "$PACKAGE_DIR/usr/bin"
mkdir -p "$PACKAGE_DIR/etc/systemd/system"
mkdir -p "$PACKAGE_DIR/usr/share/doc/$PACKAGE_NAME"

# Copy binary
cp "$PACKAGE_NAME" "$PACKAGE_DIR/usr/bin/"
chmod 755 "$PACKAGE_DIR/usr/bin/$PACKAGE_NAME"

# Copy systemd service
cp "${PACKAGE_NAME}.service" "$PACKAGE_DIR/etc/systemd/system/"

# Copy documentation
cp "README.md" "$PACKAGE_DIR/usr/share/doc/$PACKAGE_NAME/"
cp "LICENSE" "$PACKAGE_DIR/usr/share/doc/$PACKAGE_NAME/"

# Create copyright file
cat > "$PACKAGE_DIR/usr/share/doc/$PACKAGE_NAME/copyright" << EOF
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: $PACKAGE_NAME
Upstream-Contact: WhatPulse <support@whatpulse.org>
Source: https://whatpulse.org

Files: *
Copyright: 2025 WhatPulse
License: CC-BY-NC-4.0-with-additional-terms
 This work is licensed under the Creative Commons Attribution-NonCommercial 4.0
 International License with additional terms specific to WhatPulse integration.
 .
 The additional terms prohibit reverse engineering the WhatPulse communication
 protocol and tampering with data transmission.
 .
 See LICENSE file for complete terms and conditions.
EOF

# Create control file
cat > "$PACKAGE_DIR/DEBIAN/control" << EOF
Package: $PACKAGE_NAME
Version: $VERSION
Section: net
Priority: optional
Architecture: amd64
Depends: libpcap0.8
Maintainer: WhatPulse <support@whatpulse.org>
Description: External PCap service for WhatPulse network monitoring
 This service provides network packet capture capabilities for WhatPulse
 when running in AppImage or other containerized environments where
 direct PCap access is not available.
Homepage: https://whatpulse.org
EOF

# Create postinst script
cat > "$PACKAGE_DIR/DEBIAN/postinst" << 'EOF'
#!/bin/bash
set -e

case "$1" in
    configure)
        # Reload systemd daemon
        systemctl daemon-reload || true

        # Enable but don't start the service (user choice)
        systemctl enable whatpulse-pcap-service || true

        echo "WhatPulse PCap Service installed successfully."
        echo "To start the service, run: sudo systemctl start whatpulse-pcap-service"
        echo "To enable automatic startup, run: sudo systemctl enable whatpulse-pcap-service"
        ;;
esac

exit 0
EOF

# Create prerm script
cat > "$PACKAGE_DIR/DEBIAN/prerm" << 'EOF'
#!/bin/bash
set -e

case "$1" in
    remove|upgrade|deconfigure)
        # Stop the service if running
        systemctl stop whatpulse-pcap-service || true
        systemctl disable whatpulse-pcap-service || true
        ;;
esac

exit 0
EOF

# Create postrm script
cat > "$PACKAGE_DIR/DEBIAN/postrm" << 'EOF'
#!/bin/bash
set -e

case "$1" in
    purge|remove)
        # Reload systemd daemon
        systemctl daemon-reload || true
        ;;
esac

exit 0
EOF

# Make scripts executable
chmod 755 "$PACKAGE_DIR/DEBIAN/postinst"
chmod 755 "$PACKAGE_DIR/DEBIAN/prerm"
chmod 755 "$PACKAGE_DIR/DEBIAN/postrm"

# Create documentation
if [ -f "README.md" ]; then
    cp README.md "$PACKAGE_DIR/usr/share/doc/$PACKAGE_NAME/"
fi

# Create copyright file
cat > "$PACKAGE_DIR/usr/share/doc/$PACKAGE_NAME/copyright" << EOF
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: $PACKAGE_NAME
Source: https://github.com/whatpulse/external-pcap-service

Files: *
Copyright: $(date +%Y) WhatPulse
License: Proprietary
 This software is proprietary to WhatPulse.
 See https://whatpulse.org for terms and conditions.
EOF

# Build the package
dpkg-deb --build "$PACKAGE_DIR"

# Move to dist directory
mkdir -p dist
mv "$PACKAGE_DIR.deb" "dist/${PACKAGE_NAME}_${VERSION}_amd64.deb"

echo "Debian package created: dist/${PACKAGE_NAME}_${VERSION}_amd64.deb"
