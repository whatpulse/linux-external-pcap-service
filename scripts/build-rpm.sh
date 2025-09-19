#!/bin/bash
set -e

VERSION=${1:-1.0.0}
PACKAGE_NAME="whatpulse-pcap-service"
BUILD_DIR="scripts/rpm/build"
SPEC_FILE="$BUILD_DIR/$PACKAGE_NAME.spec"

echo "Building RPM package for version $VERSION"

# Clean and create build directory structure
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Create spec file
cat > "$SPEC_FILE" << EOF
Name:           $PACKAGE_NAME
Version:        $VERSION
Release:        1%{?dist}
Summary:        External PCap service for WhatPulse network monitoring
Group:          Applications/Internet
License:        Proprietary
URL:            https://whatpulse.org
BuildArch:      x86_64
Requires:       libpcap
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root

%description
This service provides network packet capture capabilities for WhatPulse
when running in AppImage or other containerized environments where
direct PCap access is not available.

The service runs with root privileges to capture network packets and
forwards them to WhatPulse via TCP connection.

%prep

%build

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}/usr/lib/systemd/system

# Copy binary and service file from current directory
cp %{_sourcedir}/$PACKAGE_NAME %{buildroot}%{_bindir}/
cp %{_sourcedir}/${PACKAGE_NAME}.service %{buildroot}/usr/lib/systemd/system/

%clean
rm -rf %{buildroot}

%files
%{_bindir}/$PACKAGE_NAME
/usr/lib/systemd/system/${PACKAGE_NAME}.service

%post
/bin/systemctl daemon-reload >/dev/null 2>&1 || :
/bin/systemctl enable $PACKAGE_NAME >/dev/null 2>&1 || :
echo "WhatPulse PCap Service installed successfully."
echo "To start the service, run: sudo systemctl start $PACKAGE_NAME"

%preun
if [ \$1 -eq 0 ] ; then
    # Package removal, not upgrade
    /bin/systemctl --no-reload disable $PACKAGE_NAME >/dev/null 2>&1 || :
    /bin/systemctl stop $PACKAGE_NAME >/dev/null 2>&1 || :
fi

%postun
/bin/systemctl daemon-reload >/dev/null 2>&1 || :

%changelog
* $(date '+%a %b %d %Y') WhatPulse Team <support@whatpulse.org> - $VERSION-1
- Initial RPM package release
EOF

# Copy source files to SOURCES directory
cp "$PACKAGE_NAME" "$BUILD_DIR/SOURCES/"
cp "${PACKAGE_NAME}.service" "$BUILD_DIR/SOURCES/"

# Build the RPM
rpmbuild --define "_topdir $(pwd)/$BUILD_DIR" -bb "$SPEC_FILE"

# Move to dist directory
mkdir -p dist
find "$BUILD_DIR/RPMS" -name "*.rpm" -exec cp {} dist/ \;

echo "RPM package created in dist/ directory"
