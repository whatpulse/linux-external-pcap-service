/*
 * WhatPulse External PCap Service - PF_RING Capture Thread
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

#ifndef PFRINGCAPTURETHREAD_H
#define PFRINGCAPTURETHREAD_H

#include "pcapcapturethread.h" // For PacketData structure
#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <mutex>
#include <atomic>
#include <cstdint>
#include <sys/socket.h>
#include <linux/if_packet.h>

// Forward declarations
class IPacketHandler;

/**
 * Thread class for capturing packets using PF_RING (PACKET_MMAP) on a specific interface
 * Provides better performance than traditional PCap through zero-copy kernel bypass
 */
class PfRingCaptureThread
{
public:
  explicit PfRingCaptureThread(const std::string &interface, bool verbose, IPacketHandler *handler);
  ~PfRingCaptureThread();

  void start();
  void stop();
  void join();
  bool isCapturing() const { return m_capturing.load(); }
  bool isReady() const { return m_ready; }
  const std::string &interfaceName() const { return m_interface; }

  // Static method to check if PF_RING is supported on the system
  static bool isSupported();

private:
  void run();
  void handlePacket(unsigned int packetLen, const u_char *packet);

  std::string m_interface;
  bool m_verbose;
  std::atomic<bool> m_capturing;
  std::atomic<bool> m_shouldStop;
  std::atomic<bool> m_ready;

  // PF_RING specific members
  int m_socket;
  struct tpacket_req m_req;
  char *m_map;
  struct iovec *m_ring;
  unsigned int m_frameIndex;

  // Performance tracking
  std::atomic<uint64_t> m_packetsProcessed;
  std::atomic<uint64_t> m_bytesProcessed;
  std::atomic<uint64_t> m_packetsDropped;
  std::chrono::steady_clock::time_point m_lastStatsReport;

  std::unique_ptr<std::thread> m_thread;
  IPacketHandler *m_handler;

  mutable std::mutex m_mutex;

  // Private helper methods
  bool initializePfRing();
  void cleanupPfRing();
  int getInterfaceIndex(const std::string &interface);
};

#endif // PFRINGCAPTURETHREAD_H
