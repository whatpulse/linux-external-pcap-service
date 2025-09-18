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

#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <queue>
#include <cstdint>
#include <pcap/pcap.h>

#define PCAP_SERVICE_VERSION "1.0.0"

// Forward declarations
struct PacketData;
class PcapCaptureThread;
class TcpClient;

/**
 * Structure for packet data transmission
 */
struct PacketData {
    uint8_t ipVersion;           // 4 or 6
    uint16_t dataLength;         // Packet length
    uint32_t timestamp;          // Packet timestamp
    std::vector<uint8_t> packetData; // Raw packet data (IP header onwards)
    std::string interfaceName;   // Interface name where packet was captured
    
    PacketData() : ipVersion(0), dataLength(0), timestamp(0) {}
};

/**
 * Main service class that manages PCap capture and network communication
 */
class PcapService {
public:
    PcapService();
    ~PcapService();

    bool initialize(const std::string& host, uint16_t port, 
                   const std::string& interface = "", bool verbose = false);
    bool start();
    void stop();
    void run();  // Main run loop

    // Called by capture threads when a packet is captured
    void onPacketCaptured(const PacketData& packet);

private:
    void connectToWhatPulse();
    void sendPacketData(const PacketData& packet);
    void networkThreadFunction();
    
    std::string m_host;
    uint16_t m_port;
    std::string m_interface;
    bool m_verbose;
    std::atomic<bool> m_running;
    
    std::unique_ptr<TcpClient> m_tcpClient;
    std::vector<std::unique_ptr<PcapCaptureThread>> m_captureThreads;
    
    // Packet queue for thread-safe communication
    std::queue<PacketData> m_packetQueue;
    std::mutex m_queueMutex;
    std::condition_variable m_queueCondition;
    
    // Network thread for handling TCP communication
    std::unique_ptr<std::thread> m_networkThread;
};

/**
 * Thread class for capturing packets on a specific interface
 */
class PcapCaptureThread {
public:
    explicit PcapCaptureThread(const std::string& interface, bool verbose, PcapService* service);
    ~PcapCaptureThread();
    
    void start();
    void stop();
    void join();
    bool isCapturing() const { return m_capturing.load(); }
    const std::string& interfaceName() const { return m_interface; }

private:
    void run();
    static void packetHandler(u_char* userData, const struct pcap_pkthdr* header, const u_char* packet);
    void handlePacket(const struct pcap_pkthdr* header, const u_char* packet);
    
    std::string m_interface;
    bool m_verbose;
    std::atomic<bool> m_capturing;
    std::atomic<bool> m_shouldStop;
    
    pcap_t* m_pcapHandle;
    std::unique_ptr<std::thread> m_thread;
    PcapService* m_service;
    
    mutable std::mutex m_mutex;
};

/**
 * Simple TCP client for communicating with WhatPulse
 */
class TcpClient {
public:
    TcpClient();
    ~TcpClient();
    
    bool connect(const std::string& host, uint16_t port);
    void disconnect();
    bool isConnected() const;
    bool send(const std::vector<uint8_t>& data);
    
    void setVerbose(bool verbose) { m_verbose = verbose; }

private:
    int m_socket;
    bool m_connected;
    bool m_verbose;
    std::string m_host;
    uint16_t m_port;
    
    mutable std::mutex m_mutex;
};

#endif // PCAPSERVICE_H
