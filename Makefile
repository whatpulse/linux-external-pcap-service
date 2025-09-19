CC=g++
CFLAGS=-std=c++17 -Wall -Wextra -O2 -pthread
LDFLAGS=-lpcap -pthread
TARGET=whatpulse-pcap-service
SOURCES=main.cpp pcapservice.cpp tcpclient.cpp pcapcapturethread.cpp
VERSION=1.0.0

# Default target
all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES) $(LDFLAGS)

# Debug build
debug: CFLAGS += -g -DDEBUG
debug: $(TARGET)

# Static build (most portable - for universal distribution)
# Note: Static builds can be complex due to system library dependencies
# This is a compromise that statically links our code but uses system libraries for complex deps
static-simple: CFLAGS += -DSTATIC_BUILD
static-simple: LDFLAGS := -lpcap -lpthread -lsystemd -lcap
static-simple: $(TARGET)

# Full static build (requires all development libraries installed)
# This may fail on systems without InfiniBand/netlink development libraries
static: CFLAGS += -DSTATIC_BUILD
static: LDFLAGS := -static -lpcap -lpthread -lnl-3 -lnl-route-3 -lnl-genl-3 -ldbus-1 -lsystemd -lcap -lm -libverbs
static: $(TARGET)

# Shared build (for packages with dependency management)
shared: $(TARGET)

# Create distributable static binary
dist-static: static-simple
	mkdir -p dist
	cp $(TARGET) dist/$(TARGET)-static
	strip dist/$(TARGET)-static
	chmod +x dist/$(TARGET)-static

# Create source distribution
dist-source:
	mkdir -p dist
	tar czf dist/$(TARGET)-$(VERSION)-source.tar.gz \
		*.cpp *.h Makefile README.md LICENSE \
		whatpulse-pcap-service.service install.sh uninstall.sh

# Clean target
clean:
	rm -f $(TARGET)
	rm -rf dist/
	rm -rf packaging/*/build/

# Install target (requires root)
install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/
	install -m 644 whatpulse-pcap-service.service /etc/systemd/system/ || echo "Service file not found, skipping systemd service installation"
	systemctl daemon-reload || echo "Failed to reload systemd daemon"

# Uninstall target
uninstall:
	systemctl stop whatpulse-pcap-service || echo "Service not running"
	systemctl disable whatpulse-pcap-service || echo "Service not enabled"
	rm -f /etc/systemd/system/whatpulse-pcap-service.service
	rm -f /usr/local/bin/$(TARGET)
	systemctl daemon-reload || echo "Failed to reload systemd daemon"

.PHONY: all debug static shared dist-static dist-source clean install uninstall
