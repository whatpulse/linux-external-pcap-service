/*
 * WhatPulse External PCap Service - Header Definitions
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

#ifndef PCAPSERVICE_H
#define PCAPSERVICE_H

#include "tcpclient.h"
#include "pcapcapturethread.h"
#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <queue>
#include <set>
#include <cstdint>

#define PCAP_SERVICE_VERSION "1.0.0"

/**
 * Main service class that manages PCap capture and network communication
 */
class PcapService
{
public:
    PcapService();
    ~PcapService();

    bool initialize(const std::string &host, uint16_t port,
                    const std::string &interface = "", bool verbose = false);
    bool start();
    void stop();
    void run(); // Main run loop

    // Called by capture threads when a packet is captured
    void onPacketCaptured(const PacketData &packet);

private:
    void connectToWhatPulse();
    void sendPacketData(const PacketData &packet);
    void networkThreadFunction();
    void networkMonitorThreadFunction();

    // Network interface discovery and monitoring
    std::vector<std::string> discoverNetworkInterfaces();
    void updateCaptureThreads(const std::vector<std::string> &currentInterfaces);
    void startCaptureThread(const std::string &interface);
    void stopCaptureThread(const std::string &interface);

    std::string m_host;
    uint16_t m_port;
    std::string m_interface;
    bool m_verbose;
    std::atomic<bool> m_running;

    std::unique_ptr<TcpClient> m_tcpClient;
    std::vector<std::unique_ptr<PcapCaptureThread>> m_captureThreads;

    // Track monitored interfaces
    std::set<std::string> m_monitoredInterfaces;
    std::mutex m_interfacesMutex;

    // Packet queue for thread-safe communication
    std::queue<PacketData> m_packetQueue;
    std::mutex m_queueMutex;
    std::condition_variable m_queueCondition;

    // Network thread for handling TCP communication
    std::unique_ptr<std::thread> m_networkThread;

    // Network monitor thread for detecting interface changes
    std::unique_ptr<std::thread> m_networkMonitorThread;
};

#endif // PCAPSERVICE_H
