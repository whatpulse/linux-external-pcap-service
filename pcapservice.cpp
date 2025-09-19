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
#include <unistd.h>
#include <ifaddrs.h>

// Performance optimization constants (matching built-in PCap monitor)
#define BUFFER_SIZE (256 * 1024 * 1024) // 256MB buffer like built-in
#define MONITOR_INTERVAL 300            // Seconds between interface checks (5 minutes)
#define LOG_LEVEL_DEBUG false           // Set to true to enable debug output

// =============================================================================
// PcapService Implementation
// =============================================================================

PcapService::PcapService()
{
    m_port = 3499;
    m_verbose = false;
    m_running = false;
}

PcapService::~PcapService()
{
    stop();
}

bool PcapService::initialize(const std::string &host, uint16_t port,
                             const std::string &interface, bool verbose)
{
    m_host = host;
    m_port = port;
    m_interface = interface;
    m_verbose = verbose;

    // Initialize TCP client
    m_tcpClient = std::make_unique<TcpClient>();
    m_tcpClient->setVerbose(verbose);

    return true;
}

bool PcapService::start()
{
    if (m_running.load())
    {
        return true;
    }

    // Check for root privileges (required for pcap)
    if (geteuid() != 0)
    {
        std::cerr << "PCap service requires root privileges. Please run with sudo." << std::endl;
        return false;
    }

    // Initialize network interfaces
    std::vector<std::string> interfaces;
    if (m_interface.empty())
    {
        // Auto-discover network interfaces
        interfaces = discoverNetworkInterfaces();
    }
    else
    {
        interfaces.push_back(m_interface);
    }

    if (interfaces.empty())
    {
        std::cerr << "No suitable network interfaces found for monitoring" << std::endl;
        return false;
    }

    // Start capture threads for initial interfaces
    updateCaptureThreads(interfaces);

    if (m_captureThreads.empty())
    {
        std::cerr << "Failed to start any capture threads" << std::endl;
        return false;
    }

    // Start network thread
    m_networkThread = std::make_unique<std::thread>(&PcapService::networkThreadFunction, this);

    // Start network monitoring thread (only if auto-discovering interfaces)
    if (m_interface.empty())
    {
        m_networkMonitorThread = std::make_unique<std::thread>(&PcapService::networkMonitorThreadFunction, this);
    }

    m_running.store(true);
    return true;
}

void PcapService::stop()
{
    if (!m_running.load())
    {
        return;
    }

    m_running.store(false);

    // Stop all capture threads
    for (auto &thread : m_captureThreads)
    {
        thread->stop();
    }

    // Wake up network threads
    m_queueCondition.notify_all();

    // Wait for network thread to finish
    if (m_networkThread && m_networkThread->joinable())
    {
        m_networkThread->join();
    }

    // Wait for network monitor thread to finish
    if (m_networkMonitorThread && m_networkMonitorThread->joinable())
    {
        m_networkMonitorThread->join();
    }

    // Wait for capture threads to finish
    for (auto &thread : m_captureThreads)
    {
        thread->join();
    }

    m_captureThreads.clear();
    m_monitoredInterfaces.clear();

    // Disconnect TCP client
    if (m_tcpClient)
    {
        m_tcpClient->disconnect();
    }

    if (m_verbose)
    {
        std::cout << "PCap service stopped" << std::endl;
    }
}

void PcapService::run()
{
    while (m_running.load())
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void PcapService::onPacketCaptured(const PacketData &packet)
{
    if (!m_running.load())
    {
        return;
    }

    if (m_verbose)
    {
        static uint64_t packetCount = 0;
        static uint64_t totalBytes = 0;
        static auto lastReport = std::chrono::steady_clock::now();

        packetCount++;
        totalBytes += packet.dataLength;

        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - lastReport);

        if (elapsed.count() >= 5)
        {
            // Report every 5 seconds for debugging purposes
            double mbps = (totalBytes * 8.0) / (elapsed.count() * 1024 * 1024);
            if (LOG_LEVEL_DEBUG)
            {
                std::cout << "Captured " << packetCount << " packets in " << elapsed.count()
                          << "s from " << packet.interfaceName << " (rate: " << std::fixed << std::setprecision(2)
                          << mbps << " Mbps)" << std::endl;
            }
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

void PcapService::networkThreadFunction()
{
    if (m_verbose)
    {
        std::cout << "Network thread started" << std::endl;
    }

    auto lastReconnectAttempt = std::chrono::steady_clock::now();
    const auto reconnectInterval = std::chrono::seconds(30);

    while (m_running.load())
    {
        // Check connection status and reconnect if needed
        if (!m_tcpClient->isConnected())
        {
            auto now = std::chrono::steady_clock::now();
            if (now - lastReconnectAttempt >= reconnectInterval)
            {
                connectToWhatPulse();
                lastReconnectAttempt = now;
            }
        }

        // Process packet queue - reduced timeout for better responsiveness
        std::unique_lock<std::mutex> lock(m_queueMutex);
        if (m_queueCondition.wait_for(lock, std::chrono::milliseconds(1), [this]
                                      { return !m_packetQueue.empty() || !m_running.load(); }))
        {
            // Process multiple packets per iteration for efficiency
            int processedCount = 0;
            while (!m_packetQueue.empty() && m_running.load() && processedCount < 100)
            {
                PacketData packet = std::move(m_packetQueue.front());
                m_packetQueue.pop();
                processedCount++;
                lock.unlock();

                if (m_tcpClient->isConnected())
                {
                    sendPacketData(packet);
                }
                else if (m_verbose)
                {
                    static auto lastWarning = std::chrono::steady_clock::now();
                    auto now = std::chrono::steady_clock::now();
                    if (now - lastWarning >= std::chrono::seconds(10))
                    {
                        std::cout << "Dropping packets - WhatPulse not connected" << std::endl;
                        lastWarning = now;
                    }
                }

                lock.lock();
            }
        }
    }

    if (m_verbose)
    {
        std::cout << "Network thread stopped" << std::endl;
    }
}

void PcapService::connectToWhatPulse()
{
    if (m_verbose)
    {
        std::cout << "Connecting to WhatPulse at " << m_host << ":" << m_port << std::endl;
    }

    m_tcpClient->connect(m_host, m_port);
}

void PcapService::sendPacketData(const PacketData &packet)
{
    if (!m_tcpClient->isConnected())
    {
        return;
    }

    // Create binary protocol data
    std::vector<uint8_t> data;

    // Calculate total size
    uint32_t totalSize = sizeof(uint8_t) +             // ipVersion
                         sizeof(uint16_t) +            // dataLength
                         sizeof(uint32_t) +            // timestamp
                         sizeof(uint16_t) +            // interface name length
                         packet.interfaceName.size() + // interface name
                         sizeof(uint32_t) +            // packet data size
                         packet.packetData.size();     // packet data

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
    if (!m_tcpClient->send(data))
    {
        if (m_verbose)
        {
            std::cerr << "Failed to send packet data" << std::endl;
        }
    }
}

std::vector<std::string> PcapService::discoverNetworkInterfaces()
{
    std::vector<std::string> interfaces;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devices;

    if (pcap_findalldevs(&devices, errbuf) == -1)
    {
        if (m_verbose)
        {
            std::cerr << "Error finding network devices: " << errbuf << std::endl;
        }
        return interfaces;
    }

    for (pcap_if_t *device = devices; device != nullptr; device = device->next)
    {
        std::string deviceName(device->name);

        // Skip loopback and other unwanted interfaces
        if (deviceName.find("lo") != std::string::npos ||
            deviceName.find("docker") != std::string::npos ||
            deviceName.find("veth") != std::string::npos ||
            deviceName.find("br-") != std::string::npos ||
            deviceName == "any" || // Skip the special "any" interface
            (device->description &&
             (std::string(device->description).find("loopback") != std::string::npos ||
              std::string(device->description).find("tunnel") != std::string::npos ||
              std::string(device->description).find("Loopback") != std::string::npos ||
              std::string(device->description).find("Tunnel") != std::string::npos ||
              std::string(device->description).find("Virtual") != std::string::npos ||
              std::string(device->description).find("Bluetooth") != std::string::npos ||
              std::string(device->description).find("Adapter for loopback") != std::string::npos)))
        {
            if (m_verbose && deviceName.length() > 0)
            {
                std::cout << "Skipping interface: " << deviceName;
                if (device->description)
                {
                    std::cout << " (" << device->description << ")";
                }
                std::cout << " - not a network interface" << std::endl;
            }
            continue;
        }

        // Only include interfaces that look like real network interfaces
        // Ethernet (eth, eno, enp, ens), WiFi (wlan, wlp), VPN (tun, tap, ppp)
        // Also include macOS-style interfaces (en0, en1, etc.)
        if (deviceName.find("eth") == 0 ||
            deviceName.find("eno") == 0 ||
            deviceName.find("enp") == 0 ||
            deviceName.find("ens") == 0 ||
            deviceName.find("en") == 0 || // macOS ethernet/wifi interfaces
            deviceName.find("wlan") == 0 ||
            deviceName.find("wlp") == 0 ||
            deviceName.find("wlo") == 0 ||
            deviceName.find("wifi") == 0 ||
            deviceName.find("tun") == 0 ||
            deviceName.find("tap") == 0 ||
            deviceName.find("ppp") == 0 ||
            deviceName.find("vpn") == 0)
        {

            interfaces.push_back(deviceName);
            if (m_verbose)
            {
                std::cout << "Found suitable network interface: " << deviceName << std::endl;
                if (device->description)
                {
                    std::cout << "  Description: " << device->description << std::endl;
                }
            }
        }
        else if (m_verbose && deviceName.length() > 0)
        {
            std::cout << "Skipping interface: " << deviceName;
            if (device->description)
            {
                std::cout << " (" << device->description << ")";
            }
            std::cout << " - not a recognized network interface pattern" << std::endl;
        }
    }

    pcap_freealldevs(devices);
    return interfaces;
}

void PcapService::updateCaptureThreads(const std::vector<std::string> &currentInterfaces)
{
    std::lock_guard<std::mutex> lock(m_interfacesMutex);

    // Find new interfaces that aren't being monitored
    for (const std::string &interface : currentInterfaces)
    {
        if (m_monitoredInterfaces.find(interface) == m_monitoredInterfaces.end())
        {
            startCaptureThread(interface);
        }
    }

    // Find interfaces that are no longer available and should be stopped
    std::vector<std::string> interfacesToRemove;
    for (const std::string &monitoredInterface : m_monitoredInterfaces)
    {
        if (std::find(currentInterfaces.begin(), currentInterfaces.end(), monitoredInterface) == currentInterfaces.end())
        {
            interfacesToRemove.push_back(monitoredInterface);
        }
    }

    for (const std::string &interface : interfacesToRemove)
    {
        stopCaptureThread(interface);
    }
}

void PcapService::startCaptureThread(const std::string &interface)
{
    // Check if we already have a thread for this interface
    for (const auto &thread : m_captureThreads)
    {
        if (thread->interfaceName() == interface)
        {
            return; // Already monitoring this interface
        }
    }

    auto captureThread = std::make_unique<PcapCaptureThread>(interface, m_verbose, this);
    captureThread->start();

    // Give thread a moment to initialize
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    if (captureThread->isCapturing())
    {
        m_captureThreads.push_back(std::move(captureThread));
        m_monitoredInterfaces.insert(interface);
        if (m_verbose)
        {
            std::cout << "Started capture thread for new interface: " << interface << std::endl;
        }
    }
    else
    {
        if (m_verbose)
        {
            std::cerr << "Failed to start capture on interface: " << interface << std::endl;
        }
    }
}

void PcapService::stopCaptureThread(const std::string &interface)
{
    auto it = std::remove_if(m_captureThreads.begin(), m_captureThreads.end(),
                             [&interface](const std::unique_ptr<PcapCaptureThread> &thread)
                             {
                                 return thread->interfaceName() == interface;
                             });

    if (it != m_captureThreads.end())
    {
        // Stop and clean up the thread
        (*it)->stop();
        (*it)->join();
        m_captureThreads.erase(it, m_captureThreads.end());
        m_monitoredInterfaces.erase(interface);

        if (m_verbose)
        {
            std::cout << "Stopped capture thread for interface: " << interface << std::endl;
        }
    }
}

void PcapService::networkMonitorThreadFunction()
{
    if (m_verbose)
    {
        std::cout << "Network monitor thread started" << std::endl;
    }

    const auto checkInterval = std::chrono::seconds(MONITOR_INTERVAL); // Check for interface changes

    while (m_running.load())
    {
        auto currentInterfaces = discoverNetworkInterfaces();
        updateCaptureThreads(currentInterfaces);

        // Sleep for the check interval, but wake up if service is stopping
        auto sleepStart = std::chrono::steady_clock::now();
        while (m_running.load())
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            auto elapsed = std::chrono::steady_clock::now() - sleepStart;
            if (elapsed >= checkInterval)
            {
                break;
            }
        }
    }

    if (m_verbose)
    {
        std::cout << "Network monitor thread stopped" << std::endl;
    }
}
