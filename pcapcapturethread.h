/*
 * WhatPulse External PCap Service - PCap Capture Thread
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

#ifndef PCAPCAPTURETHREAD_H
#define PCAPCAPTURETHREAD_H

#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <mutex>
#include <atomic>
#include <cstdint>
#include <pcap/pcap.h>

// Forward declarations
class IPacketHandler;

/**
 * Structure for packet data transmission
 */
struct PacketData
{
  uint8_t ipVersion;               // 4 or 6
  uint16_t dataLength;             // Packet length
  uint32_t timestamp;              // Packet timestamp
  std::vector<uint8_t> packetData; // Raw packet data (IP header onwards)
  std::string interfaceName;       // Interface name where packet was captured

  PacketData() : ipVersion(0), dataLength(0), timestamp(0) {}
};

/**
 * Thread class for capturing packets on a specific interface
 */
class PcapCaptureThread
{
public:
  explicit PcapCaptureThread(const std::string &interface, bool verbose, IPacketHandler *handler);
  ~PcapCaptureThread();

  void start();
  void stop();
  void join();
  bool isCapturing() const { return m_capturing.load(); }
  const std::string &interfaceName() const { return m_interface; }

private:
  void run();
  static void packetHandler(u_char *userData, const struct pcap_pkthdr *header, const u_char *packet);
  void handlePacket(const struct pcap_pkthdr *header, const u_char *packet);

  std::string m_interface;
  bool m_verbose;
  std::atomic<bool> m_capturing;
  std::atomic<bool> m_shouldStop;

  pcap_t *m_pcapHandle;
  std::unique_ptr<std::thread> m_thread;
  IPacketHandler *m_handler;

  mutable std::mutex m_mutex;
};

#endif // PCAPCAPTURETHREAD_H
