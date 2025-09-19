/*
 * WhatPulse External PCap Service - TCP Client Implementation
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

#include "tcpclient.h"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

TcpClient::TcpClient() : m_socket(-1), m_connected(false), m_verbose(false), m_port(0) {}

TcpClient::~TcpClient()
{
  disconnect();
}

bool TcpClient::connect(const std::string &host, uint16_t port)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  if (m_connected)
  {
    disconnect();
  }

  m_host = host;
  m_port = port;

  // Create socket
  m_socket = socket(AF_INET, SOCK_STREAM, 0);
  if (m_socket < 0)
  {
    if (m_verbose)
    {
      std::cerr << "Failed to create socket: " << strerror(errno) << std::endl;
    }
    return false;
  }

  // Resolve hostname
  struct hostent *hostInfo = gethostbyname(host.c_str());
  if (!hostInfo)
  {
    if (m_verbose)
    {
      std::cerr << "Failed to resolve hostname: " << host << std::endl;
    }
    close(m_socket);
    m_socket = -1;
    return false;
  }

  // Set up address
  struct sockaddr_in serverAddr;
  memset(&serverAddr, 0, sizeof(serverAddr));
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_port = htons(port);
  memcpy(&serverAddr.sin_addr, hostInfo->h_addr_list[0], hostInfo->h_length);

  // Connect
  if (::connect(m_socket, reinterpret_cast<struct sockaddr *>(&serverAddr), sizeof(serverAddr)) < 0)
  {
    if (m_verbose)
    {
      std::cerr << "Failed to connect to " << host << ":" << port << " - " << strerror(errno) << std::endl;
    }
    close(m_socket);
    m_socket = -1;
    return false;
  }

  m_connected = true;
  if (m_verbose)
  {
    std::cout << "Connected to " << host << ":" << port << std::endl;
  }

  return true;
}

void TcpClient::disconnect()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  if (m_socket >= 0)
  {
    close(m_socket);
    m_socket = -1;
  }

  if (m_connected && m_verbose)
  {
    std::cout << "Disconnected from " << m_host << ":" << m_port << std::endl;
  }

  m_connected = false;
}

bool TcpClient::isConnected() const
{
  std::lock_guard<std::mutex> lock(m_mutex);
  return m_connected;
}

bool TcpClient::send(const std::vector<uint8_t> &data)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  if (!m_connected || m_socket < 0)
  {
    return false;
  }

  size_t totalSent = 0;
  const uint8_t *dataPtr = data.data();

  while (totalSent < data.size())
  {
    ssize_t sent = ::send(m_socket, dataPtr + totalSent, data.size() - totalSent, 0);
    if (sent < 0)
    {
      if (m_verbose)
      {
        std::cerr << "Send failed: " << strerror(errno) << std::endl;
      }
      m_connected = false;
      return false;
    }
    totalSent += sent;
  }

  return true;
}
