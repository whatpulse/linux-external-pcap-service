/*
 * WhatPulse External PCap Service - PF_RING Capture Thread Implementation
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

#include "pfringcapturethread.h"
#include "packethandler.h"
#include "logger.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <chrono>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <errno.h>

// Protocol constants (matching PCap thread)
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_IPV6 0x86dd

// PF_RING optimization constants - MATCH WORKING CODE EXACTLY
#define PFRING_FRAME_SIZE 256     // Same as working code
#define PFRING_FRAME_COUNT 2048   // Same as working code
#define PFRING_BLOCK_SIZE (PFRING_FRAME_COUNT * PFRING_FRAME_SIZE)
#define PFRING_BLOCK_COUNT 1

PfRingCaptureThread::PfRingCaptureThread(bool verbose, IPacketHandler *handler)
    : m_verbose(verbose), m_capturing(false), m_shouldStop(false), 
      m_ready(false), m_socket(-1), m_map(nullptr), m_ring(nullptr), m_frameIndex(0),
      m_packetsProcessed(0), m_bytesProcessed(0), m_packetsDropped(0),
      m_lastStatsReport(std::chrono::steady_clock::now()), m_handler(handler)
{
}

PfRingCaptureThread::~PfRingCaptureThread()
{
    stop();
    join();
}

bool PfRingCaptureThread::isSupported()
{
    // Try to create a PF_PACKET socket to check support - match working code
    int testSocket = socket(PF_PACKET, SOCK_DGRAM, 0);  // Use SOCK_DGRAM like working code
    if (testSocket < 0)
    {
        return false;
    }
    close(testSocket);
    return true;
}

void PfRingCaptureThread::start()
{
    if (!initializePfRing())
    {
        LOG_ERROR("Failed to initialize PF_RING");
        return;
    }

    m_thread = std::make_unique<std::thread>(&PfRingCaptureThread::run, this);
}

void PfRingCaptureThread::stop()
{
    m_shouldStop.store(true);

    std::lock_guard<std::mutex> lock(m_mutex);
    cleanupPfRing();
}

void PfRingCaptureThread::join()
{
    if (m_thread && m_thread->joinable())
    {
        m_thread->join();
    }
}

bool PfRingCaptureThread::initializePfRing()
{
    LOG_INFO("Initializing PF_RING");

    // Create PF_PACKET socket - EXACTLY like working code
    m_socket = socket(PF_PACKET, SOCK_RAW, 0);  // Use 0 instead of htons(ETH_P_ALL) initially
    if (m_socket < 0)
    {
        LOG_ERROR("Failed to create PF_PACKET socket:");
        LOG_ERROR(strerror(errno));
        return false;
    }

    // Setup ring buffer parameters - EXACTLY match working code
    m_req.tp_frame_size = PFRING_FRAME_SIZE;
    m_req.tp_frame_nr = PFRING_FRAME_COUNT;
    m_req.tp_block_size = PFRING_FRAME_COUNT * PFRING_FRAME_SIZE;  // Calculate like working code
    m_req.tp_block_nr = PFRING_BLOCK_COUNT;

    // Set socket option for RX ring
    if (setsockopt(m_socket, SOL_PACKET, PACKET_RX_RING, &m_req, sizeof(m_req)) != 0)
    {
        LOG_ERROR("Failed to set PACKET_RX_RING:");
        LOG_ERROR(strerror(errno));
        close(m_socket);
        m_socket = -1;
        return false;
    }

    // Memory map the ring buffer
    m_map = static_cast<char*>(mmap(nullptr, m_req.tp_block_size * m_req.tp_block_nr,
                                    PROT_READ | PROT_WRITE, MAP_SHARED, m_socket, 0));
    if (m_map == MAP_FAILED)
    {
        LOG_ERROR("Failed to mmap ring buffer:");
        LOG_ERROR(strerror(errno));
        close(m_socket);
        m_socket = -1;
        m_map = nullptr;
        return false;
    }

    // Setup ring buffer structure
    m_ring = static_cast<struct iovec*>(malloc(m_req.tp_frame_nr * sizeof(struct iovec)));
    for (unsigned int i = 0; i < m_req.tp_frame_nr; i++)
    {
        m_ring[i].iov_base = static_cast<void*>(m_map + (i * m_req.tp_frame_size));
        m_ring[i].iov_len = m_req.tp_frame_size;
    }

    // Bind to interface
    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = 0;  // Bind to ALL interfaces
    addr.sll_hatype = 0;
    addr.sll_pkttype = 0;
    addr.sll_halen = 0;

    if (bind(m_socket, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0)
    {
        LOG_ERROR("Failed to bind socket:");
        LOG_ERROR(strerror(errno));
        cleanupPfRing();
        return false;
    }

    m_ready = true;
    
    // Log ring buffer configuration
    std::stringstream ss;
    ss << "PF_RING initialized successfully "
       << " - Ring buffer: " << m_req.tp_frame_nr << " frames x " << m_req.tp_frame_size 
       << " bytes = " << (m_req.tp_block_size / 1024) << " KB";
    LOG_INFO(ss.str());
    
    return true;
}

void PfRingCaptureThread::cleanupPfRing()
{
    if (m_map && m_map != MAP_FAILED)
    {
        munmap(m_map, m_req.tp_block_size * m_req.tp_block_nr);
        m_map = nullptr;
    }

    if (m_ring)
    {
        free(m_ring);
        m_ring = nullptr;
    }

    if (m_socket >= 0)
    {
        close(m_socket);
        m_socket = -1;
    }
}

void PfRingCaptureThread::run()
{
    if (!m_ready)
    {
        LOG_ERROR("PF_RING not ready");
        return;
    }

    LOG_INFO("PF_RING capture started");
    m_capturing.store(true);

    struct pollfd pfd;
    pfd.fd = m_socket;
    pfd.events = POLLIN | POLLERR;

    unsigned int frameIndex = 0; 
    const int pkt_offset = TPACKET_ALIGN(sizeof(struct tpacket_hdr)) + 
                          TPACKET_ALIGN(sizeof(struct sockaddr_ll));

    while (!m_shouldStop.load())
    {
        // Process packets
        while (!m_shouldStop.load())
        {
            struct tpacket_hdr *header = static_cast<struct tpacket_hdr*>(m_ring[frameIndex].iov_base);
            
            // Check if frame has data (TP_STATUS_USER means userspace owns the frame)
            if (!(header->tp_status & TP_STATUS_USER))
            {
                break; // No more packets available
            }

            // Update performance counters
            m_packetsProcessed.fetch_add(1);
            m_bytesProcessed.fetch_add(header->tp_len);

            // Get socket address info
            const struct sockaddr_ll *sll = reinterpret_cast<const struct sockaddr_ll*>(
                static_cast<const char*>(m_ring[frameIndex].iov_base) + TPACKET_ALIGN(sizeof(struct tpacket_hdr)));

            // Only process Ethernet frames
            if (sll->sll_hatype == ARPHRD_ETHER && header->tp_len > pkt_offset)
            {
                u_char *packet = static_cast<u_char*>(m_ring[frameIndex].iov_base) + pkt_offset + 16;
                unsigned int packetLen = header->tp_len - pkt_offset;
                
                // Validate packet bounds before processing
                if (packetLen <= 65535)
                {
                    // Copy packet data immediately while we own the frame
                    std::vector<u_char> packetCopy(packet, packet + packetLen);
                    
                    // Mark frame as processed AFTER copying data
                    header->tp_status = 0;
                    
                    // Process the copied packet data
                    handlePacket(sll->sll_ifindex, packetLen, packetCopy.data());
                }
                else
                {
                    // Packet size invalid
                    m_packetsDropped.fetch_add(1);
                    header->tp_status = 0;
                }
            }
            else
            {
                // Count dropped/non-Ethernet packets
                m_packetsDropped.fetch_add(1);
                header->tp_status = 0;
            }

            // Move to next frame
            frameIndex = (frameIndex == m_req.tp_frame_nr - 1) ? 0 : frameIndex + 1;
        }

        // Poll for new data
        pfd.revents = 0;
        poll(&pfd, 1, 100);  // 100ms timeout instead of blocking indefinitely

        // Report performance statistics periodically
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - m_lastStatsReport);
        
        int reportInterval = m_verbose ? 10 : 300; // 10s if verbose, else 5min
        if (elapsed.count() >= reportInterval && (m_packetsProcessed.load() > 0 || m_packetsDropped.load() > 0))
        {
            uint64_t packets = m_packetsProcessed.exchange(0);
            uint64_t bytes = m_bytesProcessed.exchange(0);
            uint64_t dropped = m_packetsDropped.exchange(0);
            
            if (packets > 0 || dropped > 0)
            {
                double packetsPerSec = static_cast<double>(packets) / elapsed.count();
                double mbps = (static_cast<double>(bytes) * 8.0) / (elapsed.count() * 1024.0 * 1024.0);
                
                std::stringstream ss;
                ss << "PF_RING Stats - "
                   << "Packets: " << packets << " (" << std::fixed << std::setprecision(1) << packetsPerSec << " pps), "
                   << "Rate: " << std::setprecision(2) << mbps << " Mbps";
                
                if (dropped > 0)
                {
                    ss << ", Dropped: " << dropped;
                }
                
                LOG_INFO(ss.str());
            }
            
            m_lastStatsReport = now;
        }
    }

    m_capturing.store(false);
    LOG_INFO("PF_RING capture stopped");
}

void PfRingCaptureThread::handlePacket(int ifindex, unsigned int packetLen, const u_char *packet)
{
    if (!packet || packetLen < 1 || packetLen > 65535) {
        // LOG_DEBUG("Invalid packet");
        return; // Invalid packet
    }

    // Process packet - get IP version from first nibble
    uint8_t ipVersion = (*packet) >> 4;

    // Validate IP version
    if (ipVersion != 4 && ipVersion != 6)
    {
        // LOG_DEBUG("Non-IP packet" + std::to_string(static_cast<int>(ipVersion)));
        return; // Non-IP packet
    }

    // Basic length validation
    unsigned int minHeaderSize = (ipVersion == 4) ? 20 : 40;
    if (packetLen < minHeaderSize)
    {
        // LOG_DEBUG("Packet too short");
        return; // Packet too short
    }

    // Create packet data structure
    PacketData packetData;
    packetData.ipVersion = ipVersion;
    packetData.dataLength = packetLen;
    packetData.timestamp = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                                     std::chrono::system_clock::now().time_since_epoch())
                                                     .count());
    packetData.interfaceName = std::to_string(ifindex);

    // Safe packet data copying with bounds checking
    try {
        packetData.packetData.reserve(packetLen);
        packetData.packetData.assign(packet, packet + packetLen);

        // Send to handler
        if (m_handler)
        {
            m_handler->onPacketCaptured(packetData);
        }
        else {
            LOG_DEBUG("No packet handler assigned");
        }

       // Debug logging
        if (m_verbose && packetLen >= 4)
        {
            std::stringstream debug;
            debug << "PFRING [" << ifindex << "] Captured IPv" << static_cast<int>(ipVersion)
                    << " packet - Len: " << packetLen
                    << ", Header: 0x";
            for (size_t i = 0; i < std::min(static_cast<size_t>(4), static_cast<size_t>(packetLen)); i++)
            {
                debug << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(packet[i]);
            }
            LOG_DEBUG(debug.str());
        }

    } catch (const std::exception& e) {
        // Silently drop packet on exception to avoid log spam
        return;
    }
}