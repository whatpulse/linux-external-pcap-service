/*
 * WhatPulse External PCap Service - Network Client Implementation
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

#include "networkclient.h"
#include "logger.h"
#include <chrono>
#include <thread>
#include <iostream>
#include <iomanip>
#include <sstream>

NetworkClient::NetworkClient()
    : m_port(3499), m_verbose(false), m_running(false)
{
}

NetworkClient::~NetworkClient()
{
    stop();
}

bool NetworkClient::initialize(const std::string &host, uint16_t port, bool verbose)
{
    m_host = host;
    m_port = port;
    m_verbose = verbose;

    // Initialize TCP client
    m_tcpClient = std::make_unique<TcpClient>();
    m_tcpClient->setVerbose(verbose);

    return true;
}

bool NetworkClient::start()
{
    if (m_running.load())
    {
        return true;
    }

    // Start network thread
    m_networkThread = std::make_unique<std::thread>(&NetworkClient::networkThreadFunction, this);
    m_running.store(true);

    return true;
}

void NetworkClient::stop()
{
    if (!m_running.load())
    {
        return;
    }

    m_running.store(false);

    // Wake up network thread
    m_queueCondition.notify_all();

    // Wait for network thread to finish
    if (m_networkThread && m_networkThread->joinable())
    {
        m_networkThread->join();
    }

    // Disconnect TCP client
    if (m_tcpClient)
    {
        m_tcpClient->disconnect();
    }

    LOG_INFO("Network client stopped");
}

void NetworkClient::queuePacket(const PacketData &packet)
{
    if (!m_running.load())
    {
        return;
    }

    // Performance metrics tracking (aggregated across all interfaces)
    static uint64_t packetCount = 0;
    static uint64_t totalBytes = 0;
    static uint64_t droppedPackets = 0;
    static auto lastReport = std::chrono::steady_clock::now();

    packetCount++;
    totalBytes += packet.dataLength;

    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - lastReport);

    // Check if we should report performance (handled by Logger class)
    if (elapsed.count() >= 60) // Check every minute, Logger will throttle appropriately
    {
        size_t queueSize;
        {
            std::lock_guard<std::mutex> lock(m_queueMutex);
            queueSize = m_packetQueue.size();
        }

        Logger::getInstance().logPerformance(packet.interfaceName, packetCount, totalBytes,
                                             elapsed.count(), queueSize, m_tcpClient->isConnected());

        lastReport = now;
        packetCount = 0;
        totalBytes = 0;
    }

    // Add packet to queue with overflow protection
    {
        std::lock_guard<std::mutex> lock(m_queueMutex);
        if (m_packetQueue.size() > 10000) // Prevent memory overflow
        {
            droppedPackets++;
            LOG_WARNING("Packet queue full, dropping packet. Total dropped: " + std::to_string(droppedPackets));
            return;
        }
        m_packetQueue.push(packet);
    }
    m_queueCondition.notify_one();
}

bool NetworkClient::isConnected() const
{
    return m_tcpClient && m_tcpClient->isConnected();
}

void NetworkClient::networkThreadFunction()
{
    LOG_INFO("Network thread started");

    const auto reconnectInterval = std::chrono::seconds(30);
    auto lastReconnectAttempt = std::chrono::steady_clock::now() - reconnectInterval;

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

        // Process packet queue
        std::unique_lock<std::mutex> lock(m_queueMutex);
        if (m_packetQueue.empty())
        {
            // Wait for packets or stop signal
            m_queueCondition.wait_for(lock, std::chrono::seconds(1));
            continue;
        }

        // Process up to 100 packets at once for better performance
        int processed = 0;
        while (!m_packetQueue.empty() && processed < 100 && m_running.load())
        {
            PacketData packet = m_packetQueue.front();
            m_packetQueue.pop();
            lock.unlock();

            if (m_tcpClient->isConnected())
            {
                if (!sendPacketData(packet))
                {
                    // Connection failed, packet will be lost
                    LOG_WARNING("Failed to send packet data, connection may be lost");
                }
            }

            processed++;
            lock.lock();
        }
    }

    LOG_INFO("Network thread stopped");
}

void NetworkClient::connectToWhatPulse()
{
    m_tcpClient->connect(m_host, m_port);
}

bool NetworkClient::sendPacketData(const PacketData &packet)
{
    if (!m_tcpClient->isConnected())
    {
        return false;
    }

    // Create binary protocol data
    std::vector<uint8_t> data;

    // Calculate total size
    uint32_t totalSize = sizeof(uint8_t) +                         // IP version
                         sizeof(uint16_t) +                         // data length
                         sizeof(uint32_t) +                         // timestamp
                         sizeof(uint16_t) +                         // interface name length
                         packet.interfaceName.size() +              // interface name
                         sizeof(uint32_t) +                         // packet data size
                         packet.packetData.size();                  // packet data

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
        return false;
    }
    
    // Debug logging for packet data analysis
    if (m_verbose)
    {
        std::stringstream debug;
        debug << "NET [" << packet.interfaceName << "] Sent IPv" << static_cast<int>(packet.ipVersion)
              << " packet - Size: " << totalSize 
              << ", DataLen: " << packet.dataLength
              << ", PktDataSize: " << packet.packetData.size();
        LOG_DEBUG(debug.str());
    }
    
    return true;
}
