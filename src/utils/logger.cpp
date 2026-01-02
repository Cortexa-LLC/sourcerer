// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "utils/logger.h"

namespace sourcerer {
namespace utils {

Logger& Logger::Instance() {
  static Logger instance;
  return instance;
}

void Logger::Debug(const std::string& message) {
  if (level_ <= LogLevel::DEBUG) {
    Log(LogLevel::DEBUG, "[DEBUG] ", message);
  }
}

void Logger::Info(const std::string& message) {
  if (level_ <= LogLevel::INFO) {
    Log(LogLevel::INFO, "[INFO] ", message);
  }
}

void Logger::Warning(const std::string& message) {
  if (level_ <= LogLevel::WARNING) {
    Log(LogLevel::WARNING, "[WARNING] ", message);
  }
}

void Logger::Error(const std::string& message) {
  if (level_ <= LogLevel::ERROR) {
    Log(LogLevel::ERROR, "[ERROR] ", message);
  }
}

void Logger::Log(LogLevel level, const std::string& prefix,
                 const std::string& message) {
  std::ostream& stream = (level == LogLevel::ERROR) ? std::cerr : std::cout;
  stream << prefix << message << std::endl;
}

}  // namespace utils
}  // namespace sourcerer
