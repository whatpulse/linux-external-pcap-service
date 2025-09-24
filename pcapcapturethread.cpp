/*
 * WhatPulse External PCap Service - PCap Capture Thread Implementation
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

#include "pcapcapturethread.h"
#include "pcapservice.h"
#include "logger.h"
#include <iostream>
#include <cstring>
#include <chrono>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <unistd.h>

// Protocol constants
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_IPV6 0x86dd

// Performance optimization constants (matching built-in PCap monitor)
#define DEFAULT_SNAPLEN 9000

PcapCaptureThread::PcapCaptureThread(const std::string &interface, bool verbose, PcapService *service)
{
  m_interface = interface;
  m_verbose = verbose;
  m_capturing = false;
  m_shouldStop = false;
  m_pcapHandle = nullptr;
  m_service = service;
}

PcapCaptureThread::~PcapCaptureThread()
{
  stop();
  join();
}

void PcapCaptureThread::start()
{
  m_thread = std::make_unique<std::thread>(&PcapCaptureThread::run, this);
}

void PcapCaptureThread::stop()
{
  m_shouldStop.store(true);

  std::lock_guard<std::mutex> lock(m_mutex);
  if (m_pcapHandle)
  {
    pcap_breakloop(m_pcapHandle);
  }
}

void PcapCaptureThread::join()
{
  if (m_thread && m_thread->joinable())
  {
    m_thread->join();
  }
}

void PcapCaptureThread::run()
{
  char errbuf[PCAP_ERRBUF_SIZE];

  LOG_INFO("Starting capture on interface: " + m_interface);

  // Open pcap handle
  m_pcapHandle = pcap_open_live(m_interface.c_str(),
                                DEFAULT_SNAPLEN, // optimized snap length
                                1,               // promiscuous mode
                                1,               // timeout (ms) - reduced for better performance
                                errbuf);

  if (!m_pcapHandle)
  {
    LOG_ERROR("Unable to open interface " + m_interface + ": " + std::string(errbuf));
    return;
  }

  // Set filter to capture only TCP and UDP traffic
  struct bpf_program filter;
  if (pcap_compile(m_pcapHandle, &filter, "tcp or udp", 1, PCAP_NETMASK_UNKNOWN) == -1)
  {
    LOG_ERROR("Unable to compile filter for interface " + m_interface + ": " + std::string(pcap_geterr(m_pcapHandle)));
    pcap_close(m_pcapHandle);
    m_pcapHandle = nullptr;
    return;
  }

  if (pcap_setfilter(m_pcapHandle, &filter) == -1)
  {
    LOG_ERROR("Unable to set filter for interface " + m_interface + ": " + std::string(pcap_geterr(m_pcapHandle)));
    pcap_freecode(&filter);
    pcap_close(m_pcapHandle);
    m_pcapHandle = nullptr;
    return;
  }

  pcap_freecode(&filter);
  m_capturing.store(true);

  LOG_INFO("Capture started successfully on interface: " + m_interface);

  // Start packet capture loop
  while (!m_shouldStop.load())
  {
    int result = pcap_dispatch(m_pcapHandle, 1000, packetHandler, reinterpret_cast<u_char *>(this));
    if (result == -1)
    {
      // Error occurred
      if (!m_shouldStop.load())
      {
        LOG_ERROR("Error in pcap_dispatch for interface " + m_interface + ": " + std::string(pcap_geterr(m_pcapHandle)));
      }
      break;
    }
    else if (result == -2)
    {
      // Loop was broken
      break;
    }

    // No sleep needed with larger batch size - let it run at full speed
  }

  m_capturing.store(false);

  {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_pcapHandle)
    {
      pcap_close(m_pcapHandle);
      m_pcapHandle = nullptr;
    }
  }

  LOG_INFO("Capture stopped on interface: " + m_interface);
}

void PcapCaptureThread::packetHandler(u_char *userData, const struct pcap_pkthdr *header, const u_char *packet)
{
  PcapCaptureThread *thread = reinterpret_cast<PcapCaptureThread *>(userData);
  thread->handlePacket(header, packet);
}

void PcapCaptureThread::handlePacket(const struct pcap_pkthdr *header, const u_char *packet)
{
  if (m_shouldStop.load())
  {
    return;
  }

  // Parse Ethernet header
  const struct ether_header *ethHeader = reinterpret_cast<const struct ether_header *>(packet);

  uint16_t etherType = ntohs(ethHeader->ether_type);
  uint8_t ipVersion = 0;

  if (etherType == ETHERTYPE_IP)
  {
    ipVersion = 4;
  }
  else if (etherType == ETHERTYPE_IPV6)
  {
    ipVersion = 6;
  }
  else
  {
    // Not IP traffic, ignore
    return;
  }

  // Create packet data structure
  PacketData packetData;
  packetData.ipVersion = ipVersion;
  packetData.dataLength = header->caplen;
  packetData.timestamp = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                                   std::chrono::system_clock::now().time_since_epoch())
                                                   .count());
  packetData.interfaceName = m_interface;

  // Copy packet data starting from IP header (skip Ethernet header)
  const u_char *ipPacket = packet + sizeof(struct ether_header);
  uint32_t ipPacketLength = header->caplen - sizeof(struct ether_header);

  packetData.packetData.assign(ipPacket, ipPacket + ipPacketLength);

  // Send to service
  if (m_service)
  {
    m_service->onPacketCaptured(packetData);
  }
}
