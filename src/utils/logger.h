// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_UTILS_LOGGER_H_
#define SOURCERER_UTILS_LOGGER_H_

#include <iostream>
#include <string>

namespace sourcerer {
namespace utils {

// Log levels
enum class LogLevel {
  DEBUG,
  INFO,
  WARNING,
  ERROR,
};

// Simple logger class
class Logger {
 public:
  static Logger& Instance();

  void SetLevel(LogLevel level) { level_ = level; }
  LogLevel GetLevel() const { return level_; }

  void Debug(const std::string& message);
  void Info(const std::string& message);
  void Warning(const std::string& message);
  void Error(const std::string& message);

  // Prevent copying
  Logger(const Logger&) = delete;
  Logger& operator=(const Logger&) = delete;

 private:
  Logger() : level_(LogLevel::INFO) {}

  void Log(LogLevel level, const std::string& prefix, const std::string& message);

  LogLevel level_;
};

// Convenience macros
#define LOG_DEBUG(msg) sourcerer::utils::Logger::Instance().Debug(msg)
#define LOG_INFO(msg) sourcerer::utils::Logger::Instance().Info(msg)
#define LOG_WARNING(msg) sourcerer::utils::Logger::Instance().Warning(msg)
#define LOG_ERROR(msg) sourcerer::utils::Logger::Instance().Error(msg)

}  // namespace utils
}  // namespace sourcerer

#endif  // SOURCERER_UTILS_LOGGER_H_
