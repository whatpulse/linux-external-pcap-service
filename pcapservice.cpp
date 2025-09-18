/*
 * WhatPulse External PCap Service - Core Implementation
 * 
 * Copyright (c) 2025 WhatPulse. All rights reserved.
 * 
 * Licensed under CC BY-NC 4.0 with additional terms.
 * See LICENSE file for complete terms and conditions.
 * 
 * NOTICE: This software integrates with WhatPulse services. Reverse engineering
 * the communication protocol or tampering with data transmission is prohibited.
 * 
 * For licensing questions: support@whatpulse.org
 */

#include "pcapservice.h"
#include <iostream>
#include <cstring>
#include <chrono>
#include <thread>
#include <algorithm>
#include <iomanip>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>

// Protocol constants
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_IPV6 0x86dd

// Performance optimization constants (matching built-in PCap monitor)
#define DEFAULT_SNAPLEN 9000
#define BUFFER_SIZE (256 * 1024 * 1024)  // 256MB buffer like built-in

// =============================================================================
// TcpClient Implementation
// =============================================================================

TcpClient::TcpClient() : m_socket(-1), m_connected(false), m_verbose(false), m_port(0) {}

TcpClient::~TcpClient() {
    disconnect();
}

bool TcpClient::connect(const std::string& host, uint16_t port) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_connected) {
        disconnect();
    }
    
    m_host = host;
    m_port = port;
    
    // Create socket
    m_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (m_socket < 0) {
        if (m_verbose) {
            std::cerr << "Failed to create socket: " << strerror(errno) << std::endl;
        }
        return false;
    }
    
    // Resolve hostname
    struct hostent* hostInfo = gethostbyname(host.c_str());
    if (!hostInfo) {
        if (m_verbose) {
            std::cerr << "Failed to resolve hostname: " << host << std::endl;
        }
        close(m_socket);
        m_socket = -1;
        return false;
    }
    
    // Set up address
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    memcpy(&serverAddr.sin_addr, hostInfo->h_addr_list[0], hostInfo->h_length);
    
    // Connect
    if (::connect(m_socket, reinterpret_cast<struct sockaddr*>(&serverAddr), sizeof(serverAddr)) < 0) {
        if (m_verbose) {
            std::cerr << "Failed to connect to " << host << ":" << port << " - " << strerror(errno) << std::endl;
        }
        close(m_socket);
        m_socket = -1;
        return false;
    }
    
    m_connected = true;
    if (m_verbose) {
        std::cout << "Connected to " << host << ":" << port << std::endl;
    }
    
    return true;
}

void TcpClient::disconnect() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_socket >= 0) {
        close(m_socket);
        m_socket = -1;
    }
    
    if (m_connected && m_verbose) {
        std::cout << "Disconnected from " << m_host << ":" << m_port << std::endl;
    }
    
    m_connected = false;
}

bool TcpClient::isConnected() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_connected;
}

bool TcpClient::send(const std::vector<uint8_t>& data) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (!m_connected || m_socket < 0) {
        return false;
    }
    
    size_t totalSent = 0;
    const uint8_t* dataPtr = data.data();
    
    while (totalSent < data.size()) {
        ssize_t sent = ::send(m_socket, dataPtr + totalSent, data.size() - totalSent, 0);
        if (sent < 0) {
            if (m_verbose) {
                std::cerr << "Send failed: " << strerror(errno) << std::endl;
            }
            m_connected = false;
            return false;
        }
        totalSent += sent;
    }
    
    return true;
}

// =============================================================================
// PcapService Implementation
// =============================================================================

PcapService::PcapService() : m_port(3499), m_verbose(false), m_running(false) {}

PcapService::~PcapService() {
    stop();
}

bool PcapService::initialize(const std::string& host, uint16_t port, 
                            const std::string& interface, bool verbose) {
    m_host = host;
    m_port = port;
    m_interface = interface;
    m_verbose = verbose;
    
    // Initialize TCP client
    m_tcpClient = std::make_unique<TcpClient>();
    m_tcpClient->setVerbose(verbose);
    
    return true;
}

bool PcapService::start() {
    if (m_running.load()) {
        return true;
    }
    
    // Check for root privileges (required for pcap)
    if (geteuid() != 0) {
        std::cerr << "PCap service requires root privileges. Please run with sudo." << std::endl;
        return false;
    }
    
    // Find network interfaces to monitor
    std::vector<std::string> interfaces;
    if (m_interface.empty()) {
        // Monitor all suitable interfaces
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_if_t* devices;
        if (pcap_findalldevs(&devices, errbuf) == -1) {
            std::cerr << "Error finding network devices: " << errbuf << std::endl;
            return false;
        }
        
        for (pcap_if_t* device = devices; device != nullptr; device = device->next) {
            std::string deviceName(device->name);
            
            // Skip loopback and other unwanted interfaces
            if (deviceName.find("lo") != std::string::npos || 
                deviceName.find("docker") != std::string::npos ||
                deviceName.find("veth") != std::string::npos ||
                deviceName.find("br-") != std::string::npos ||
                deviceName == "any" ||  // Skip the special "any" interface
                (device->description && 
                 (std::string(device->description).find("loopback") != std::string::npos ||
                  std::string(device->description).find("tunnel") != std::string::npos ||
                  std::string(device->description).find("Loopback") != std::string::npos ||
                  std::string(device->description).find("Tunnel") != std::string::npos ||
                  std::string(device->description).find("Virtual") != std::string::npos ||
                  std::string(device->description).find("Bluetooth") != std::string::npos ||
                  std::string(device->description).find("Adapter for loopback") != std::string::npos))) {
                if (m_verbose) {
                    std::cout << "Skipping interface: " << deviceName;
                    if (device->description) {
                        std::cout << " (" << device->description << ")";
                    }
                    std::cout << " - not a network interface" << std::endl;
                }
                continue;
            }
            
            // Only include interfaces that look like real network interfaces
            // Ethernet (eth, eno, enp, ens), WiFi (wlan, wlp), VPN (tun, tap, ppp)
            if (deviceName.find("eth") == 0 || 
                deviceName.find("eno") == 0 ||
                deviceName.find("enp") == 0 ||
                deviceName.find("ens") == 0 ||
                deviceName.find("wlan") == 0 ||
                deviceName.find("wlp") == 0 ||
                deviceName.find("wlo") == 0 ||
                deviceName.find("wifi") == 0 ||
                deviceName.find("tun") == 0 ||
                deviceName.find("tap") == 0 ||
                deviceName.find("ppp") == 0 ||
                deviceName.find("vpn") == 0) {
                
                interfaces.push_back(deviceName);
                if (m_verbose) {
                    std::cout << "Found suitable network interface: " << deviceName << std::endl;
                    if (device->description) {
                        std::cout << "  Description: " << device->description << std::endl;
                    }
                }
            } else if (m_verbose) {
                std::cout << "Skipping interface: " << deviceName;
                if (device->description) {
                    std::cout << " (" << device->description << ")";
                }
                std::cout << " - not a network interface" << std::endl;
            }
        }
        
        pcap_freealldevs(devices);
    } else {
        interfaces.push_back(m_interface);
    }
    
    if (interfaces.empty()) {
        std::cerr << "No suitable network interfaces found for monitoring" << std::endl;
        return false;
    }
    
    // Create capture threads for each interface
    for (const std::string& iface : interfaces) {
        auto captureThread = std::make_unique<PcapCaptureThread>(iface, m_verbose, this);
        captureThread->start();
        
        // Give thread a moment to initialize
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        if (captureThread->isCapturing()) {
            m_captureThreads.push_back(std::move(captureThread));
            if (m_verbose) {
                std::cout << "Started capture thread for interface: " << iface << std::endl;
            }
        } else {
            std::cerr << "Failed to start capture on interface: " << iface << std::endl;
        }
    }
    
    if (m_captureThreads.empty()) {
        std::cerr << "Failed to start any capture threads" << std::endl;
        return false;
    }
    
    // Start network thread
    m_networkThread = std::make_unique<std::thread>(&PcapService::networkThreadFunction, this);
    
    m_running.store(true);
    return true;
}

void PcapService::stop() {
    if (!m_running.load()) {
        return;
    }
    
    m_running.store(false);
    
    // Stop all capture threads
    for (auto& thread : m_captureThreads) {
        thread->stop();
    }
    
    // Wake up network thread
    m_queueCondition.notify_all();
    
    // Wait for network thread to finish
    if (m_networkThread && m_networkThread->joinable()) {
        m_networkThread->join();
    }
    
    // Wait for capture threads to finish
    for (auto& thread : m_captureThreads) {
        thread->join();
    }
    
    m_captureThreads.clear();
    
    // Disconnect TCP client
    if (m_tcpClient) {
        m_tcpClient->disconnect();
    }
    
    if (m_verbose) {
        std::cout << "PCap service stopped" << std::endl;
    }
}

void PcapService::run() {
    while (m_running.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void PcapService::onPacketCaptured(const PacketData& packet) {
    if (!m_running.load()) {
        return;
    }
    
    if (m_verbose) {
        static uint64_t packetCount = 0;
        static uint64_t totalBytes = 0;
        static auto lastReport = std::chrono::steady_clock::now();
        
        packetCount++;
        totalBytes += packet.dataLength;
        
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - lastReport);
        
        if (elapsed.count() >= 5) { // Report every 5 seconds
            double mbps = (totalBytes * 8.0) / (elapsed.count() * 1024 * 1024);
            std::cout << "Captured " << packetCount << " packets in " << elapsed.count() 
                      << "s from " << packet.interfaceName << " (rate: " << std::fixed << std::setprecision(2) 
                      << mbps << " Mbps)" << std::endl;
            lastReport = now;
            packetCount = 0;
            totalBytes = 0;
        }
    }
    
    // Add packet to queue
    {
        std::lock_guard<std::mutex> lock(m_queueMutex);
        m_packetQueue.push(packet);
    }
    m_queueCondition.notify_one();
}

void PcapService::networkThreadFunction() {
    if (m_verbose) {
        std::cout << "Network thread started" << std::endl;
    }
    
    auto lastReconnectAttempt = std::chrono::steady_clock::now();
    const auto reconnectInterval = std::chrono::seconds(5);
    
    while (m_running.load()) {
        // Check connection status and reconnect if needed
        if (!m_tcpClient->isConnected()) {
            auto now = std::chrono::steady_clock::now();
            if (now - lastReconnectAttempt >= reconnectInterval) {
                connectToWhatPulse();
                lastReconnectAttempt = now;
            }
        }
        
        // Process packet queue - reduced timeout for better responsiveness
        std::unique_lock<std::mutex> lock(m_queueMutex);
        if (m_queueCondition.wait_for(lock, std::chrono::milliseconds(1), [this] { return !m_packetQueue.empty() || !m_running.load(); })) {
            // Process multiple packets per iteration for efficiency
            int processedCount = 0;
            while (!m_packetQueue.empty() && m_running.load() && processedCount < 100) {
                PacketData packet = std::move(m_packetQueue.front());
                m_packetQueue.pop();
                processedCount++;
                lock.unlock();
                
                if (m_tcpClient->isConnected()) {
                    sendPacketData(packet);
                } else if (m_verbose) {
                    static auto lastWarning = std::chrono::steady_clock::now();
                    auto now = std::chrono::steady_clock::now();
                    if (now - lastWarning >= std::chrono::seconds(10)) {
                        std::cout << "Dropping packets - WhatPulse not connected" << std::endl;
                        lastWarning = now;
                    }
                }
                
                lock.lock();
            }
        }
    }
    
    if (m_verbose) {
        std::cout << "Network thread stopped" << std::endl;
    }
}

void PcapService::connectToWhatPulse() {
    if (m_verbose) {
        std::cout << "Connecting to WhatPulse at " << m_host << ":" << m_port << std::endl;
    }
    
    m_tcpClient->connect(m_host, m_port);
}

void PcapService::sendPacketData(const PacketData& packet) {
    if (!m_tcpClient->isConnected()) {
        return;
    }
    
    // Create binary protocol data
    std::vector<uint8_t> data;
    
    // Calculate total size
    uint32_t totalSize = sizeof(uint8_t) +           // ipVersion
                        sizeof(uint16_t) +           // dataLength  
                        sizeof(uint32_t) +           // timestamp
                        sizeof(uint16_t) +           // interface name length
                        packet.interfaceName.size() + // interface name
                        sizeof(uint32_t) +           // packet data size
                        packet.packetData.size();    // packet data
    
    // Reserve space
    data.reserve(sizeof(uint32_t) + totalSize);
    
    // Write total size (big-endian)
    data.push_back((totalSize >> 24) & 0xFF);
    data.push_back((totalSize >> 16) & 0xFF);
    data.push_back((totalSize >> 8) & 0xFF);
    data.push_back(totalSize & 0xFF);
    
    // Write packet data
    data.push_back(packet.ipVersion);
    
    // Write data length (big-endian)
    data.push_back((packet.dataLength >> 8) & 0xFF);
    data.push_back(packet.dataLength & 0xFF);
    
    // Write timestamp (big-endian)
    data.push_back((packet.timestamp >> 24) & 0xFF);
    data.push_back((packet.timestamp >> 16) & 0xFF);
    data.push_back((packet.timestamp >> 8) & 0xFF);
    data.push_back(packet.timestamp & 0xFF);
    
    // Write interface name length (big-endian)
    uint16_t nameLen = packet.interfaceName.size();
    data.push_back((nameLen >> 8) & 0xFF);
    data.push_back(nameLen & 0xFF);
    
    // Write interface name
    data.insert(data.end(), packet.interfaceName.begin(), packet.interfaceName.end());
    
    // Write packet data size (big-endian)
    uint32_t packetDataSize = packet.packetData.size();
    data.push_back((packetDataSize >> 24) & 0xFF);
    data.push_back((packetDataSize >> 16) & 0xFF);
    data.push_back((packetDataSize >> 8) & 0xFF);
    data.push_back(packetDataSize & 0xFF);
    
    // Write packet data
    data.insert(data.end(), packet.packetData.begin(), packet.packetData.end());
    
    // Send data
    if (!m_tcpClient->send(data)) {
        if (m_verbose) {
            std::cerr << "Failed to send packet data" << std::endl;
        }
    }
}

// =============================================================================
// PcapCaptureThread Implementation
// =============================================================================

PcapCaptureThread::PcapCaptureThread(const std::string& interface, bool verbose, PcapService* service)
    : m_interface(interface)
    , m_verbose(verbose)
    , m_capturing(false)
    , m_shouldStop(false)
    , m_pcapHandle(nullptr)
    , m_service(service) {
}

PcapCaptureThread::~PcapCaptureThread() {
    stop();
    join();
}

void PcapCaptureThread::start() {
    m_thread = std::make_unique<std::thread>(&PcapCaptureThread::run, this);
}

void PcapCaptureThread::stop() {
    m_shouldStop.store(true);
    
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_pcapHandle) {
        pcap_breakloop(m_pcapHandle);
    }
}

void PcapCaptureThread::join() {
    if (m_thread && m_thread->joinable()) {
        m_thread->join();
    }
}

void PcapCaptureThread::run() {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (m_verbose) {
        std::cout << "Starting capture on interface: " << m_interface << std::endl;
    }
    
    // Open pcap handle
    m_pcapHandle = pcap_open_live(m_interface.c_str(), 
                                  DEFAULT_SNAPLEN,  // optimized snap length
                                  1,      // promiscuous mode
                                  1,      // timeout (ms) - reduced for better performance
                                  errbuf);
    
    if (!m_pcapHandle) {
        std::cerr << "Unable to open interface " << m_interface << ": " << errbuf << std::endl;
        return;
    }
    
    // Set filter to capture only TCP and UDP traffic
    struct bpf_program filter;
    if (pcap_compile(m_pcapHandle, &filter, "tcp or udp", 1, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Unable to compile filter for interface " << m_interface << ": " 
                  << pcap_geterr(m_pcapHandle) << std::endl;
        pcap_close(m_pcapHandle);
        m_pcapHandle = nullptr;
        return;
    }
    
    if (pcap_setfilter(m_pcapHandle, &filter) == -1) {
        std::cerr << "Unable to set filter for interface " << m_interface << ": " 
                  << pcap_geterr(m_pcapHandle) << std::endl;
        pcap_freecode(&filter);
        pcap_close(m_pcapHandle);
        m_pcapHandle = nullptr;
        return;
    }
    
    pcap_freecode(&filter);
    m_capturing.store(true);
    
    if (m_verbose) {
        std::cout << "Capture started successfully on interface: " << m_interface << std::endl;
    }
    
    // Start packet capture loop
    while (!m_shouldStop.load()) {
        int result = pcap_dispatch(m_pcapHandle, 1000, packetHandler, reinterpret_cast<u_char*>(this));
        if (result == -1) {
            // Error occurred
            if (!m_shouldStop.load()) {
                std::cerr << "Error in pcap_dispatch for interface " << m_interface << ": " 
                          << pcap_geterr(m_pcapHandle) << std::endl;
            }
            break;
        } else if (result == -2) {
            // Loop was broken
            break;
        }
        
        // No sleep needed with larger batch size - let it run at full speed
    }
    
    m_capturing.store(false);
    
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_pcapHandle) {
            pcap_close(m_pcapHandle);
            m_pcapHandle = nullptr;
        }
    }
    
    if (m_verbose) {
        std::cout << "Capture stopped on interface: " << m_interface << std::endl;
    }
}

void PcapCaptureThread::packetHandler(u_char* userData, const struct pcap_pkthdr* header, const u_char* packet) {
    PcapCaptureThread* thread = reinterpret_cast<PcapCaptureThread*>(userData);
    thread->handlePacket(header, packet);
}

void PcapCaptureThread::handlePacket(const struct pcap_pkthdr* header, const u_char* packet) {
    if (m_shouldStop.load()) {
        return;
    }
    
    // Parse Ethernet header
    const struct ether_header* ethHeader = reinterpret_cast<const struct ether_header*>(packet);
    
    uint16_t etherType = ntohs(ethHeader->ether_type);
    uint8_t ipVersion = 0;
    
    if (etherType == ETHERTYPE_IP) {
        ipVersion = 4;
    } else if (etherType == ETHERTYPE_IPV6) {
        ipVersion = 6;
    } else {
        // Not IP traffic, ignore
        return;
    }
    
    // Create packet data structure
    PacketData packetData;
    packetData.ipVersion = ipVersion;
    packetData.dataLength = header->caplen;
    packetData.timestamp = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    packetData.interfaceName = m_interface;
    
    // Copy packet data starting from IP header (skip Ethernet header)
    const u_char* ipPacket = packet + sizeof(struct ether_header);
    uint32_t ipPacketLength = header->caplen - sizeof(struct ether_header);
    
    packetData.packetData.assign(ipPacket, ipPacket + ipPacketLength);
    
    // Send to service
    if (m_service) {
        m_service->onPacketCaptured(packetData);
    }
}
