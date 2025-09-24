/*
 * WhatPulse External PCap Service - Logger Header
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

#pragma once

#include <string>
#include <fstream>
#include <mutex>
#include <sstream>
#include <chrono>
#include <iomanip>

enum class LogLevel
{
  DEBUG = 0,
  INFO = 1,
  WARNING = 2,
  ERROR = 3
};

class Logger
{
public:
  static Logger &getInstance();

  void initialize(const std::string &logFile, LogLevel level = LogLevel::INFO, bool verbose = false);
  void setLevel(LogLevel level) { m_level = level; }
  void setVerbose(bool verbose) { m_verbose = verbose; }

  void log(LogLevel level, const std::string &message);
  void debug(const std::string &message) { log(LogLevel::DEBUG, message); }
  void info(const std::string &message) { log(LogLevel::INFO, message); }
  void warning(const std::string &message) { log(LogLevel::WARNING, message); }
  void error(const std::string &message) { log(LogLevel::ERROR, message); }

  // Performance logging with throttling
  void logPerformance(const std::string &interfaceName, uint64_t packetCount, uint64_t totalBytes,
                      double seconds, size_t queueSize, bool isConnected);

  // Connection state logging
  void logConnectionAttempt(const std::string &host, uint16_t port);
  void logConnectionSuccess(const std::string &host, uint16_t port);
  void logConnectionFailed(const std::string &host, uint16_t port, const std::string &error);
  void logDisconnected(const std::string &host, uint16_t port);
  void logSendError(const std::string &error);

private:
  Logger() = default;
  std::string getCurrentTimestamp();
  std::string levelToString(LogLevel level);
  bool shouldLogPerformance();

  std::ofstream m_logFile;
  std::mutex m_mutex;
  LogLevel m_level = LogLevel::INFO;
  bool m_verbose = false;

  // Performance logging throttling
  std::chrono::steady_clock::time_point m_lastPerformanceLog;
  std::chrono::seconds m_performanceInterval{300};       // 5 minutes default
  std::chrono::seconds m_verbosePerformanceInterval{10}; // 10 seconds in verbose mode
};

// Convenience macros
#define LOG_DEBUG(msg) Logger::getInstance().debug(msg)
#define LOG_INFO(msg) Logger::getInstance().info(msg)
#define LOG_WARNING(msg) Logger::getInstance().warning(msg)
#define LOG_ERROR(msg) Logger::getInstance().error(msg)
