/*
 * WhatPulse External PCap Service - TCP Client
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

#ifndef TCPCLIENT_H
#define TCPCLIENT_H

#include <string>
#include <vector>
#include <mutex>
#include <cstdint>

/**
 * Simple TCP client for communicating with WhatPulse
 */
class TcpClient
{
public:
  TcpClient();
  ~TcpClient();

  bool connect(const std::string &host, uint16_t port);
  void disconnect();
  bool isConnected() const;
  bool send(const std::vector<uint8_t> &data);

  void setVerbose(bool verbose) { m_verbose = verbose; }

private:
  int m_socket;
  bool m_connected;
  bool m_verbose;
  std::string m_host;
  uint16_t m_port;

  mutable std::mutex m_mutex;
};

#endif // TCPCLIENT_H
