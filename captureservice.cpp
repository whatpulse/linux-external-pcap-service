/*
 * WhatPulse External PCap Service - Capture Service Implementation
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

#include "captureservice.h"
#include "packethandler.h"
#include "logger.h"
#include <iostream>
#include <algorithm>
#include <chrono>
#include <thread>
#include <pcap/pcap.h>
#include <unistd.h>
#include <ifaddrs.h>

CaptureService::CaptureService()
    : m_verbose(false), m_running(false), m_preferPfRing(true)
{
    m_pfRingSupported = PfRingCaptureThread::isSupported();
    
    if (m_pfRingSupported)
    {
        LOG_INFO("PF_RING support detected - will use high-performance packet capture");
    }
    else
    {
        LOG_INFO("PF_RING not available - falling back to traditional PCap");
    }
}

CaptureService::~CaptureService()
{
    stop();
}

bool CaptureService::initialize(const std::string &interface, bool verbose, PacketCallback callback)
{
    m_interface = interface;
    m_verbose = verbose;
    m_packetCallback = callback;

    return true;
}

bool CaptureService::start()
{
    if (m_running.load())
    {
        return true;
    }

    // Check for root privileges (required for pcap)
    if (geteuid() != 0)
    {
        LOG_ERROR("Capture service requires root privileges. Please run with sudo.");
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
        LOG_ERROR("No suitable network interfaces found for monitoring");
        return false;
    }

    // Try to start global PF_RING thread first
    bool pfRingStarted = false;
    if (m_preferPfRing && m_pfRingSupported)
    {
        pfRingStarted = startGlobalPfRingThread();
        if (pfRingStarted)
        {
            LOG_INFO("Started global PF_RING capture thread (captures all interfaces)");
        }
        else
        {
            LOG_WARNING("Failed to start global PF_RING, falling back to per-interface PCap");
        }
    }

    // If PF_RING failed or not preferred, start per-interface PCap threads
    if (!pfRingStarted)
    {
        updateCaptureThreads(interfaces);
        
        if (m_captureThreads.empty())
        {
            LOG_ERROR("Failed to start any capture threads");
            return false;
        }
    }

    // Start network monitoring thread (only if using PCap and auto-discovering interfaces)
    if (!pfRingStarted && m_interface.empty())
    {
        m_networkMonitorThread = std::make_unique<std::thread>(&CaptureService::networkMonitorThreadFunction, this);
    }

    m_running.store(true);
    return true;
}

void CaptureService::stop()
{
    if (!m_running.load())
    {
        return;
    }

    m_running.store(false);

    // Stop all capture threads
    stopAllCaptureThreads();

    // Wait for network monitor thread to finish
    if (m_networkMonitorThread && m_networkMonitorThread->joinable())
    {
        m_networkMonitorThread->join();
    }

    // Wait for PCap threads to finish
    for (auto &thread : m_captureThreads)
    {
        thread->join();
    }

    // Wait for global PF_RING thread to finish
    if (m_globalPfRingThread)
    {
        m_globalPfRingThread->join();
    }

    m_captureThreads.clear();
    m_globalPfRingThread.reset();
    m_monitoredInterfaces.clear();

    LOG_INFO("Capture service stopped");
}

void CaptureService::onPacketCaptured(const PacketData &packet)
{
    if (!m_running.load() || !m_packetCallback)
    {
        return;
    }

    // Forward packet to callback (which will be the NetworkClient)
    m_packetCallback(packet);
}

std::vector<std::string> CaptureService::discoverNetworkInterfaces()
{
    std::vector<std::string> interfaces;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devices;

    if (pcap_findalldevs(&devices, errbuf) == -1)
    {
        LOG_ERROR("Error finding network devices: " + std::string(errbuf));
        return interfaces;
    }

    for (pcap_if_t *device = devices; device != nullptr; device = device->next)
    {
        // Skip loopback interfaces
        if (device->flags & PCAP_IF_LOOPBACK)
        {
            continue;
        }

        // Skip interfaces without addresses
        if (!device->addresses)
        {
            continue;
        }

        std::string interfaceName = device->name;
        
        // Skip known virtual interfaces
        if (interfaceName.find("veth") != std::string::npos ||
            interfaceName.find("docker") != std::string::npos ||
            interfaceName.find("br-") != std::string::npos ||
            interfaceName == "lo")
        {
            continue;
        }

        interfaces.push_back(interfaceName);
        LOG_INFO("Discovered network interface: " + interfaceName);
    }

    pcap_freealldevs(devices);
    return interfaces;
}

void CaptureService::updateCaptureThreads(const std::vector<std::string> &currentInterfaces)
{
    std::lock_guard<std::mutex> lock(m_interfacesMutex);

    // Find new interfaces that aren't being monitored
    for (const std::string &interface : currentInterfaces)
    {
        if (m_monitoredInterfaces.find(interface) == m_monitoredInterfaces.end())
        {
            LOG_INFO("Starting capture on new interface: " + interface);
            startCaptureThread(interface);
            m_monitoredInterfaces.insert(interface);
        }
    }

    // Find interfaces that are no longer available and should be stopped
    std::vector<std::string> interfacesToRemove;
    std::copy_if(m_monitoredInterfaces.begin(), m_monitoredInterfaces.end(),
                 std::back_inserter(interfacesToRemove),
                 [&currentInterfaces](const std::string &monitoredInterface) {
                     return std::find(currentInterfaces.begin(), currentInterfaces.end(), monitoredInterface) == currentInterfaces.end();
                 });

    for (const std::string &interface : interfacesToRemove)
    {
        LOG_INFO("Stopping capture on removed interface: " + interface);
        stopCaptureThread(interface);
        m_monitoredInterfaces.erase(interface);
    }
}

void CaptureService::startCaptureThread(const std::string &interface)
{
    // Check if we already have a PCap thread for this interface
    // (PF_RING is now global and doesn't need per-interface checking)
    if (std::any_of(m_captureThreads.begin(), m_captureThreads.end(),
                    [&interface](const std::unique_ptr<PcapCaptureThread> &thread) {
                        return thread->interfaceName() == interface;
                    }))
    {
        return; // Already monitoring this interface
    }

    // Only start PCap threads now (PF_RING is handled globally)
    bool success = false;
    
    try {
        auto pcapThread = std::make_unique<PcapCaptureThread>(interface, m_verbose, this);
        pcapThread->start();

        // Give thread a moment to initialize
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        if (pcapThread->isCapturing())
        {
            m_captureThreads.push_back(std::move(pcapThread));
            success = true;
            LOG_INFO("Started PCap capture thread for interface: " + interface);
        }
    } catch (const std::exception& e) {
        LOG_ERROR("Exception starting PCap for " + interface + ": " + std::string(e.what()));
    }

    if (!success)
    {
        LOG_ERROR("Failed to start PCap thread for interface: " + interface);
    }
}

void CaptureService::stopCaptureThread(const std::string &interface)
{
    bool stopped = false;

    // Only handle PCap threads (PF_RING is global)
    // First find and stop threads, then erase them (avoid use-after-move)
    for (auto it = m_captureThreads.begin(); it != m_captureThreads.end(); )
    {
        if ((*it)->interfaceName() == interface)
        {
            (*it)->stop();
            (*it)->join();
            it = m_captureThreads.erase(it);
            stopped = true;
        }
        else
        {
            ++it;
        }
    }

    if (stopped)
    {
        LOG_INFO("Stopped PCap thread for interface: " + interface);
    }
}

void CaptureService::networkMonitorThreadFunction()
{
    LOG_INFO("Network monitor thread started");

    const auto checkInterval = std::chrono::seconds(MONITOR_INTERVAL); // Check for interface changes

    while (m_running.load())
    {
        std::this_thread::sleep_for(checkInterval);

        if (!m_running.load())
        {
            break;
        }

        // Re-discover interfaces and update capture threads
        std::vector<std::string> currentInterfaces = discoverNetworkInterfaces();
        updateCaptureThreads(currentInterfaces);
    }

    LOG_INFO("Network monitor thread stopped");
}


bool CaptureService::startGlobalPfRingThread()
{
    if (m_globalPfRingThread)
    {
        return true; // Already started
    }

    try {
        // Create global PF_RING thread with empty interface name (captures all)
        m_globalPfRingThread = std::make_unique<PfRingCaptureThread>(m_verbose, this);
        m_globalPfRingThread->start();

        // Give thread a moment to initialize
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        if (m_globalPfRingThread->isCapturing() && m_globalPfRingThread->isReady())
        {
            return true;
        }
        else
        {
            m_globalPfRingThread.reset();
            return false;
        }
    } catch (const std::exception& e) {
        LOG_ERROR("Exception starting global PF_RING thread: " + std::string(e.what()));
        m_globalPfRingThread.reset();
        return false;
    }
}

void CaptureService::stopGlobalPfRingThread()
{
    if (m_globalPfRingThread)
    {
        m_globalPfRingThread->stop();
    }
}

void CaptureService::stopAllCaptureThreads()
{
    // Stop global PF_RING thread
    stopGlobalPfRingThread();

    // Stop all PCap threads
    for (auto &thread : m_captureThreads)
    {
        thread->stop();
    }
}
