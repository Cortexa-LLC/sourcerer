// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_OUTPUT_DATA_COLLECTOR_H_
#define SOURCERER_OUTPUT_DATA_COLLECTOR_H_

#include <cstdint>
#include <vector>

#include "core/address_map.h"
#include "core/binary.h"

namespace sourcerer {
namespace output {

// String detection result
struct StringDetectionResult {
  bool looks_like_string;
  bool has_high_bit;
  bool has_control_char;
  int printable_count;
};

// Data collection result
struct DataCollectionResult {
  std::vector<uint8_t> bytes;
  uint32_t next_address;  // Address after last collected byte
};

// Component responsible for collecting data from binary
// Handles string detection, string collection, and binary data collection
class DataCollector {
 public:
  explicit DataCollector(const core::Binary* binary) : binary_(binary) {}

  // Detect if bytes at address look like a string
  // Examines first 'lookahead' bytes for printable characters
  StringDetectionResult DetectString(
      uint32_t address,
      uint32_t end_address,
      size_t lookahead = 4) const;

  // Collect string data until null terminator or non-printable
  // Stops at labeled addresses to ensure they get their own output lines
  DataCollectionResult CollectStringData(
      uint32_t start_address,
      uint32_t end_address,
      const core::AddressMap* address_map,
      size_t max_length = 128) const;

  // Collect binary data (up to max_bytes)
  // Stops at labeled addresses to ensure they get their own output lines
  DataCollectionResult CollectBinaryData(
      uint32_t start_address,
      uint32_t end_address,
      const core::AddressMap* address_map,
      size_t max_bytes = 8) const;

  // Helper: Check if byte is printable (for string detection)
  static bool IsPrintable(uint8_t byte) {
    uint8_t ch = byte & 0x7F;  // Strip high bit
    return ch >= 0x20 && ch < 0x7F;
  }

 private:
  const core::Binary* binary_;
};

}  // namespace output
}  // namespace sourcerer

#endif  // SOURCERER_OUTPUT_DATA_COLLECTOR_H_
