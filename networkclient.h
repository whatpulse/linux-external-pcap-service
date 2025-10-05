/*
 * WhatPulse External PCap Service - Network Client
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

#ifndef NETWORKCLIENT_H
#define NETWORKCLIENT_H

#include "tcpclient.h"
#include "pcapcapturethread.h" // For PacketData
#include <string>
#include <memory>
#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <queue>

/**
 * Manages network communication with WhatPulse, including packet queue processing
 * and automatic reconnection logic
 */
class NetworkClient
{
public:
    NetworkClient();
    ~NetworkClient();

    bool initialize(const std::string &host, uint16_t port, bool verbose = false);
    bool start();
    void stop();

    // Queue a packet for transmission
    void queuePacket(const PacketData &packet);

    // Connection status
    bool isConnected() const;

private:
    void networkThreadFunction();
    void connectToWhatPulse();
    bool sendBatchedPackets(const std::vector<PacketData> &batch);
    void flushBatch();

    std::string m_host;
    uint16_t m_port;
    bool m_verbose;
    std::atomic<bool> m_running;

    std::unique_ptr<TcpClient> m_tcpClient;

    // Batching configuration
    static constexpr auto BATCH_FLUSH_INTERVAL = std::chrono::milliseconds(1000);
    static constexpr size_t MAX_BATCH_SIZE_BYTES = 16 * 1024 * 1024; // 16MB max batch
    static constexpr size_t MAX_BATCH_PACKET_COUNT = 50000; // Max packets per batch

    // Batching state
    std::vector<PacketData> m_batchBuffer;
    size_t m_batchSizeBytes;
    std::chrono::steady_clock::time_point m_lastFlush;
    std::mutex m_batchMutex;

    // Batch queue for thread-safe communication
    std::queue<std::vector<PacketData>> m_packetQueue;
    std::mutex m_queueMutex;
    std::condition_variable m_queueCondition;

    // Network thread for handling TCP communication
    std::unique_ptr<std::thread> m_networkThread;
};

#endif // NETWORKCLIENT_H
