/*
 * WhatPulse External PCap Service - Capture Service
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

#ifndef CAPTURESERVICE_H
#define CAPTURESERVICE_H

#include "pcapcapturethread.h"
#include "pfringcapturethread.h"
#include "packethandler.h"
#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <mutex>
#include <atomic>
#include <set>
#include <functional>

/**
 * Callback function type for packet capture
 */
using PacketCallback = std::function<void(const PacketData&)>;

/**
 * Manages packet capture threads and interface monitoring
 * Separated from network communication concerns
 */
class CaptureService : public IPacketHandler
{
public:
    CaptureService();
    ~CaptureService();

    bool initialize(const std::string &interface, bool verbose, PacketCallback callback);
    bool start();
    void stop();

    // Called by capture threads when a packet is captured
    void onPacketCaptured(const PacketData &packet);

private:
    // Network interface discovery and monitoring
    std::vector<std::string> discoverNetworkInterfaces();
    void updateCaptureThreads(const std::vector<std::string> &currentInterfaces);
    void startCaptureThread(const std::string &interface);
    void stopCaptureThread(const std::string &interface);
    void networkMonitorThreadFunction();
    
    // PF_RING specific methods
    bool startPfRingCaptureThread(const std::string &interface);
    void stopPfRingCaptureThread(const std::string &interface);
    void stopAllCaptureThreads();

    std::string m_interface;
    bool m_verbose;
    std::atomic<bool> m_running;
    PacketCallback m_packetCallback;

    std::vector<std::unique_ptr<PcapCaptureThread>> m_captureThreads;
    std::vector<std::unique_ptr<PfRingCaptureThread>> m_pfringCaptureThreads;

    // Capture method preference
    bool m_preferPfRing;
    bool m_pfRingSupported;

    // Track monitored interfaces
    std::set<std::string> m_monitoredInterfaces;
    std::mutex m_interfacesMutex;

    // Network monitor thread for detecting interface changes
    std::unique_ptr<std::thread> m_networkMonitorThread;

    // Performance optimization constants (matching built-in PCap monitor)
    static constexpr int MONITOR_INTERVAL = 300; // Seconds between interface checks (5 minutes)
};

#endif // CAPTURESERVICE_H
