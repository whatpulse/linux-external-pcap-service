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
#include <numeric>

NetworkClient::NetworkClient()
    : m_port(3499), m_verbose(false), m_running(false),
      m_batchSizeBytes(0), m_lastFlush(std::chrono::steady_clock::now())
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
        if (m_tcpClient->isConnected())
        {
            LOG_INFO("Disconnecting from WhatPulse");
        }
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

    // Add packet to batch buffer
    {
        std::lock_guard<std::mutex> lock(m_batchMutex);
        m_batchBuffer.push_back(packet);
        m_batchSizeBytes += packet.packetData.size();
    }

    // Check if we should flush the batch
    bool shouldFlush = false;
    std::string flushReason;

    {
        std::lock_guard<std::mutex> lock(m_batchMutex);
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - m_lastFlush);

        // Flush conditions
        if (elapsed >= BATCH_FLUSH_INTERVAL)
        {
            shouldFlush = true;
            flushReason = "timer";
        }
        else if (m_batchSizeBytes >= MAX_BATCH_SIZE_BYTES)
        {
            shouldFlush = true;
            flushReason = "size limit (" + std::to_string(m_batchSizeBytes / 1024 / 1024) + " MB)";
        }
        else if (m_batchBuffer.size() >= MAX_BATCH_PACKET_COUNT)
        {
            shouldFlush = true;
            flushReason = "packet count (" + std::to_string(m_batchBuffer.size()) + ")";
        }
    }

    if (shouldFlush)
    {
        if (m_verbose && flushReason != "timer")
        {
            LOG_INFO("Forced batch flush due to " + flushReason);
        }
        flushBatch();
    }
}

bool NetworkClient::isConnected() const
{
    return m_tcpClient && m_tcpClient->isConnected();
}

void NetworkClient::flushBatch()
{
    std::vector<PacketData> batchToSend;
    size_t batchBytes = 0;

    {
        std::lock_guard<std::mutex> lock(m_batchMutex);
        if (m_batchBuffer.empty())
        {
            return;
        }

        // Move batch to local variable
        batchToSend = std::move(m_batchBuffer);
        batchBytes = m_batchSizeBytes;

        // Reset batch state
        m_batchBuffer.clear();
        m_batchSizeBytes = 0;
        m_lastFlush = std::chrono::steady_clock::now();
    }

    // Queue the batch for sending
    {
        std::lock_guard<std::mutex> lock(m_queueMutex);
        if (m_packetQueue.size() > 100) // Reduced queue limit since each entry is a batch
        {
            LOG_WARNING("Batch queue full (" + std::to_string(m_packetQueue.size()) +
                       " batches), dropping batch of " + std::to_string(batchToSend.size()) + " packets");
            return;
        }

        m_packetQueue.push(batchToSend);
    }
    m_queueCondition.notify_one();

    if (m_verbose)
    {
        LOG_DEBUG("Flushed batch: " + std::to_string(batchToSend.size()) +
                 " packets, " + std::to_string(batchBytes / 1024) + " KB");
    }
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

        // Flush any pending batch on timer
        bool shouldFlush = false;
        {
            std::lock_guard<std::mutex> lock(m_batchMutex);
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - m_lastFlush);

            if (!m_batchBuffer.empty() && elapsed >= BATCH_FLUSH_INTERVAL)
            {
                shouldFlush = true;
            }
        }

        if (shouldFlush)
        {
            flushBatch();
        }

        // Process batch queue
        std::unique_lock<std::mutex> lock(m_queueMutex);
        if (m_packetQueue.empty())
        {
            // Wait for batches or stop signal (shorter wait for timer-based flushing)
            m_queueCondition.wait_for(lock, std::chrono::milliseconds(100));
            continue;
        }

        // Process batches from queue
        while (!m_packetQueue.empty() && m_running.load())
        {
            std::vector<PacketData> batch = m_packetQueue.front();
            m_packetQueue.pop();
            lock.unlock();

            if (m_tcpClient->isConnected())
            {
                if (!sendBatchedPackets(batch))
                {
                    LOG_WARNING("Failed to send batch of " + std::to_string(batch.size()) + " packets - connection lost");
                }
            }
            else
            {
                if (m_verbose)
                {
                    LOG_WARNING("Not connected, dropping batch of " + std::to_string(batch.size()) + " packets");
                }
            }

            lock.lock();
        }
    }

    // Flush any remaining batch before shutdown
    flushBatch();

    LOG_INFO("Network thread stopped");
}

void NetworkClient::connectToWhatPulse()
{
    m_tcpClient->connect(m_host, m_port);
}

bool NetworkClient::sendBatchedPackets(const std::vector<PacketData> &batch)
{
    if (!m_tcpClient->isConnected() || batch.empty())
    {
        return false;
    }

    // Calculate total size for the batch
    uint32_t totalSize = sizeof(uint32_t) + // batchCount field
                         std::accumulate(batch.begin(), batch.end(), 0u,
                                       [](uint32_t sum, const PacketData &packet) {
                                           return sum + sizeof(uint8_t) +                     // IP version
                                                  sizeof(uint16_t) +                     // data length
                                                  sizeof(uint32_t) +                     // timestamp
                                                  sizeof(uint16_t) +                     // interface name length
                                                  packet.interfaceName.size() +          // interface name
                                                  sizeof(uint32_t) +                     // packet data size
                                                  packet.packetData.size();              // packet data
                                       });

    // Create binary protocol data
    std::vector<uint8_t> data;
    data.reserve(sizeof(uint32_t) + totalSize);

    // Write total size header (big-endian)
    data.push_back((totalSize >> 24) & 0xFF);
    data.push_back((totalSize >> 16) & 0xFF);
    data.push_back((totalSize >> 8) & 0xFF);
    data.push_back(totalSize & 0xFF);

    // Write batch count (big-endian)
    uint32_t batchCount = batch.size();
    data.push_back((batchCount >> 24) & 0xFF);
    data.push_back((batchCount >> 16) & 0xFF);
    data.push_back((batchCount >> 8) & 0xFF);
    data.push_back(batchCount & 0xFF);

    // Write each packet in the batch
    for (const auto &packet : batch)
    {
        // Write IP version
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
    }

    // Send data via TCP
    if (!m_tcpClient->send(data))
    {
        return false;
    }

    // Debug logging
    if (m_verbose)
    {
        LOG_DEBUG("Sent batch: " + std::to_string(batchCount) + " packets, " +
                 std::to_string(data.size() / 1024) + " KB total");
    }

    return true;
}
