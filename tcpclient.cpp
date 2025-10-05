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
#include "logger.h"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <sys/time.h>

TcpClient::TcpClient() : m_socket(-1), m_connected(false), m_verbose(false), m_port(0) {}

TcpClient::~TcpClient()
{
  forceDisconnect();
}

bool TcpClient::connect(const std::string &host, uint16_t port)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  if (m_connected)
  {
    forceDisconnect();
  }

  m_host = host;
  m_port = port;

  Logger::getInstance().logConnectionAttempt(host, port);

  // Create socket
  m_socket = socket(AF_INET, SOCK_STREAM, 0);
  if (m_socket < 0)
  {
    Logger::getInstance().logConnectionFailed(host, port, "Failed to create socket: " + std::string(strerror(errno)));
    return false;
  }

  // Set socket options for better error detection
  int keepalive = 1;
  if (setsockopt(m_socket, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive)) < 0)
  {
    Logger::getInstance().logConnectionFailed(host, port, "Failed to set SO_KEEPALIVE: " + std::string(strerror(errno)));
  }

  // Set timeout for send operations
  struct timeval timeout;
  timeout.tv_sec = 5;  // 5 second timeout
  timeout.tv_usec = 0;
  if (setsockopt(m_socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0)
  {
    Logger::getInstance().logConnectionFailed(host, port, "Failed to set SO_SNDTIMEO: " + std::string(strerror(errno)));
  }

  // Resolve hostname
  struct hostent *hostInfo = gethostbyname(host.c_str());
  if (!hostInfo)
  {
    Logger::getInstance().logConnectionFailed(host, port, "Failed to resolve hostname: " + host);
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

  // Set connection timeout
  struct timeval connect_timeout;
  connect_timeout.tv_sec = 10;  // 10 second connection timeout
  connect_timeout.tv_usec = 0;
  if (setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO, &connect_timeout, sizeof(connect_timeout)) < 0)
  {
    Logger::getInstance().logConnectionFailed(host, port, "Failed to set SO_RCVTIMEO: " + std::string(strerror(errno)));
  }

  // Connect
  if (::connect(m_socket, reinterpret_cast<struct sockaddr *>(&serverAddr), sizeof(serverAddr)) < 0)
  {
    Logger::getInstance().logConnectionFailed(host, port, strerror(errno));
    close(m_socket);
    m_socket = -1;
    return false;
  }

  m_connected = true;
  Logger::getInstance().logConnectionSuccess(host, port);

  return true;
}

void TcpClient::disconnect()
{
  std::lock_guard<std::mutex> lock(m_mutex);
  forceDisconnect();
}

bool TcpClient::isConnected() const
{
  std::lock_guard<std::mutex> lock(m_mutex);
  
  if (!m_connected || m_socket < 0)
  {
    return false;
  }
  
  // Check socket error state
  int error = 0;
  socklen_t len = sizeof(error);
  if (getsockopt(m_socket, SOL_SOCKET, SO_ERROR, &error, &len) != 0 || error != 0)
  {
    return false;
  }
  
  // Perform a non-blocking recv to detect if peer closed connection
  char dummy;
  ssize_t result = recv(m_socket, &dummy, 1, MSG_PEEK | MSG_DONTWAIT);
  
  if (result == 0)
  {
    // Connection closed by peer
    return false;
  }
  else if (result < 0)
  {
    if (errno == ECONNRESET || errno == ENOTCONN || errno == EPIPE)
    {
      // Connection is broken
      return false;
    }
  }
  
  return true;
}

void TcpClient::forceDisconnect()
{
  // This method assumes mutex is already locked by caller
  if (m_socket >= 0)
  {
    close(m_socket);
    m_socket = -1;
  }

  if (m_connected)
  {
    Logger::getInstance().logDisconnected(m_host, m_port);
    m_connected = false;
  }
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
    ssize_t sent = ::send(m_socket, dataPtr + totalSent, data.size() - totalSent, MSG_NOSIGNAL);
    if (sent < 0)
    {
      // Handle different error conditions
      if (errno == EPIPE || errno == ECONNRESET || errno == ENOTCONN || errno == EBADF)
      {
        // Connection was closed by peer or socket is invalid
        Logger::getInstance().logSendError("Connection lost: " + std::string(strerror(errno)));
        forceDisconnect();
        return false;
      }
      else if (errno == EAGAIN || errno == EWOULDBLOCK)
      {
        // Temporary error, could retry but for now treat as failure
        Logger::getInstance().logSendError("Send would block: " + std::string(strerror(errno)));
        return false;
      }
      else
      {
        // Other error
        Logger::getInstance().logSendError("Send error: " + std::string(strerror(errno)));
        forceDisconnect();
        return false;
      }
    }
    else if (sent == 0)
    {
      // Connection closed by peer
      Logger::getInstance().logSendError("Connection closed by peer");
      forceDisconnect();
      return false;
    }
    totalSent += sent;
  }

  return true;
}
