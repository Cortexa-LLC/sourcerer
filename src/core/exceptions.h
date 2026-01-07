// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_CORE_EXCEPTIONS_H_
#define SOURCERER_CORE_EXCEPTIONS_H_

#include <cstdint>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace sourcerer {

// Base exception for all Sourcerer errors
class SourcererException : public std::runtime_error {
 public:
  explicit SourcererException(const std::string& message)
      : std::runtime_error(message) {}
};

// Analysis errors - code flow analysis failures
class AnalysisException : public SourcererException {
 public:
  explicit AnalysisException(const std::string& message,
                            uint32_t address = 0)
      : SourcererException(FormatMessage(message, address)),
        address_(address) {}

  uint32_t address() const { return address_; }

 private:
  uint32_t address_;

  static std::string FormatMessage(const std::string& msg, uint32_t addr) {
    if (addr == 0) {
      return "Analysis error: " + msg;
    }
    std::ostringstream oss;
    oss << "Analysis error at $" << std::hex << std::uppercase
        << std::setw(4) << std::setfill('0') << addr << ": " << msg;
    return oss.str();
  }
};

// Disassembly errors - instruction decoding failures
class DisassemblyException : public SourcererException {
 public:
  explicit DisassemblyException(const std::string& message,
                               uint32_t address,
                               const std::vector<uint8_t>& bytes = {})
      : SourcererException(FormatMessage(message, address, bytes)),
        address_(address),
        bytes_(bytes) {}

  uint32_t address() const { return address_; }
  const std::vector<uint8_t>& bytes() const { return bytes_; }

 private:
  uint32_t address_;
  std::vector<uint8_t> bytes_;

  static std::string FormatMessage(const std::string& msg,
                                  uint32_t addr,
                                  const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    oss << "Disassembly error at $" << std::hex << std::uppercase
        << std::setw(4) << std::setfill('0') << addr << ": " << msg;

    if (!bytes.empty()) {
      oss << " [bytes:";
      for (size_t i = 0; i < bytes.size() && i < 8; ++i) {
        oss << " " << std::hex << std::uppercase << std::setw(2)
            << std::setfill('0') << static_cast<int>(bytes[i]);
      }
      if (bytes.size() > 8) {
        oss << " ...";
      }
      oss << "]";
    }

    return oss.str();
  }
};

// Binary loading errors - file I/O and format errors
class BinaryException : public SourcererException {
 public:
  explicit BinaryException(const std::string& message,
                          const std::string& file_path = "")
      : SourcererException(FormatMessage(message, file_path)),
        file_path_(file_path) {}

  const std::string& file_path() const { return file_path_; }

 private:
  std::string file_path_;

  static std::string FormatMessage(const std::string& msg,
                                  const std::string& path) {
    if (path.empty()) {
      return "Binary error: " + msg;
    }
    return "Binary error (" + path + "): " + msg;
  }
};

// Disk extraction errors - disk image and file extraction failures
class DiskException : public SourcererException {
 public:
  explicit DiskException(const std::string& message,
                        const std::string& disk_path = "",
                        const std::string& file_name = "")
      : SourcererException(FormatMessage(message, disk_path, file_name)),
        disk_path_(disk_path),
        file_name_(file_name) {}

  const std::string& disk_path() const { return disk_path_; }
  const std::string& file_name() const { return file_name_; }

 private:
  std::string disk_path_;
  std::string file_name_;

  static std::string FormatMessage(const std::string& msg,
                                  const std::string& disk,
                                  const std::string& file) {
    std::ostringstream oss;
    oss << "Disk error";
    if (!disk.empty()) {
      oss << " (" << disk;
      if (!file.empty()) {
        oss << " / " << file;
      }
      oss << ")";
    }
    oss << ": " << msg;
    return oss.str();
  }
};

// Formatting errors - output generation failures
class FormatterException : public SourcererException {
 public:
  explicit FormatterException(const std::string& message)
      : SourcererException("Formatter error: " + message) {}
};

// Configuration errors - invalid settings or options
class ConfigException : public SourcererException {
 public:
  explicit ConfigException(const std::string& message)
      : SourcererException("Configuration error: " + message) {}
};

}  // namespace sourcerer

#endif  // SOURCERER_CORE_EXCEPTIONS_H_
