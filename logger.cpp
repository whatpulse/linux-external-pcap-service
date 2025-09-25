/*
 * WhatPulse External PCap Service - Logger Implementation
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

#include "logger.h"
#include <iostream>
#include <iomanip>
#include <ctime>

Logger &Logger::getInstance()
{
  static Logger instance;
  return instance;
}

void Logger::initialize(const std::string &logFile, LogLevel level, bool verbose)
{
  m_level = level;
  m_verbose = verbose;

  // Set performance logging intervals based on verbose mode
  if (verbose)
  {
    m_performanceInterval = m_verbosePerformanceInterval;
  }

  if (!logFile.empty())
  {
    m_logFile.close();
    m_logFile.open(logFile, std::ios::app);
    if (!m_logFile.is_open())
    {
      std::cerr << "Failed to open log file: " << logFile << std::endl;
      return;
    }
  }

  // Initial log entry
  std::stringstream ss;
  ss << "Logger initialized - Level: " << levelToString(level)
     << ", Verbose: " << (verbose ? "Yes" : "No")
     << ", Performance reports every: " << m_performanceInterval.count() << " seconds";
  log(LogLevel::INFO, ss.str());
}

void Logger::log(LogLevel level, const std::string &message)
{
  if (level < m_level)
  {
    return;
  }

  std::string logEntry = getCurrentTimestamp() + " [" + levelToString(level) + "] " + message;

  bool isOpen = m_logFile.is_open();
  if (isOpen)
  {
    m_logFile << logEntry << std::endl;
    m_logFile.flush();
  }
  if(!isOpen || m_verbose)
  {
    // Fallback to console if file logging fails
    if (level >= LogLevel::ERROR)
    {
      std::cerr << logEntry << std::endl;
    }
    else
    {
      std::cout << logEntry << std::endl;
    }
  }
}

void Logger::logPerformance(const std::string &interfaceName, uint64_t packetCount, uint64_t totalBytes,
                            double seconds, size_t queueSize, bool isConnected)
{
  if (!shouldLogPerformance())
  {
    return;
  }

  double mbps = (totalBytes * 8.0) / (seconds * 1024 * 1024);
  double pps = packetCount / seconds;

  std::stringstream ss;
  ss << "PERF [" << interfaceName << "] "
     << "Packets: " << packetCount << " (" << std::fixed << std::setprecision(1) << pps << " pps), "
     << "Rate: " << std::setprecision(2) << mbps << " Mbps, "
     << "Queue: " << queueSize << " packets, "
     << "TCP: " << (isConnected ? "Connected" : "Disconnected");

  log(LogLevel::INFO, ss.str());
}

void Logger::logConnectionAttempt(const std::string &host, uint16_t port)
{
  std::stringstream ss;
  ss << "TCP: Attempting to connect to " << host << ":" << port;
  log(LogLevel::INFO, ss.str());
}

void Logger::logConnectionSuccess(const std::string &host, uint16_t port)
{
  std::stringstream ss;
  ss << "TCP: Successfully connected to " << host << ":" << port;
  log(LogLevel::INFO, ss.str());
}

void Logger::logConnectionFailed(const std::string &host, uint16_t port, const std::string &error)
{
  std::stringstream ss;
  ss << "TCP: Failed to connect to " << host << ":" << port << " - " << error;
  log(LogLevel::WARNING, ss.str());
}

void Logger::logDisconnected(const std::string &host, uint16_t port)
{
  std::stringstream ss;
  ss << "TCP: Disconnected from " << host << ":" << port;
  log(LogLevel::INFO, ss.str());
}

void Logger::logSendError(const std::string &error)
{
  std::stringstream ss;
  ss << "TCP: Send failed - " << error;
  log(LogLevel::WARNING, ss.str());
}

std::string Logger::getCurrentTimestamp()
{
  auto now = std::chrono::system_clock::now();
  auto time_t = std::chrono::system_clock::to_time_t(now);
  auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(
                          now.time_since_epoch()) %
                      1000;

  std::stringstream ss;
  ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
  ss << "." << std::setfill('0') << std::setw(3) << milliseconds.count();

  return ss.str();
}

std::string Logger::levelToString(LogLevel level)
{
  switch (level)
  {
  case LogLevel::VERBOSE:
    return "VERBOSE";
  case LogLevel::INFO:
    return "INFO";
  case LogLevel::WARNING:
    return "WARN";
  case LogLevel::ERROR:
    return "ERROR";
  default:
    return "UNKNOWN";
  }
}

bool Logger::shouldLogPerformance()
{
  auto now = std::chrono::steady_clock::now();
  if (now - m_lastPerformanceLog >= m_performanceInterval)
  {
    m_lastPerformanceLog = now;
    return true;
  }
  return false;
}
