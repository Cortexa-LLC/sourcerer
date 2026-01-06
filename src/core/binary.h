// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_CORE_BINARY_H_
#define SOURCERER_CORE_BINARY_H_

#include <cstdint>
#include <string>
#include <vector>

namespace sourcerer {
namespace core {

// Represents a single segment of a binary
struct BinarySegment {
  std::vector<uint8_t> data;
  uint32_t load_address;

  uint32_t size() const { return static_cast<uint32_t>(data.size()); }
  uint32_t end_address() const { return load_address + size(); }
};

// Represents a binary program loaded into memory
// Supports both single-segment (flat) and multi-segment (CoCo LOADM) binaries
class Binary {
 public:
  Binary();
  Binary(const std::vector<uint8_t>& data, uint32_t load_address);

  // Load binary from file (auto-detects format)
  static Binary LoadFromFile(const std::string& path, uint32_t load_address);

  // Accessors
  const std::vector<uint8_t>& data() const { return data_; }
  uint32_t load_address() const { return load_address_; }
  uint32_t size() const { return static_cast<uint32_t>(data_.size()); }
  const std::string& source_file() const { return source_file_; }
  const std::string& file_type() const { return file_type_; }

  // Multi-segment accessors
  bool is_multi_segment() const { return !segments_.empty(); }
  const std::vector<BinarySegment>& segments() const { return segments_; }
  uint32_t entry_point() const { return entry_point_; }

  // Mutators
  void set_load_address(uint32_t address) { load_address_ = address; }
  void set_source_file(const std::string& file) { source_file_ = file; }
  void set_file_type(const std::string& type) { file_type_ = type; }
  void set_entry_point(uint32_t address) { entry_point_ = address; }
  void add_segment(const BinarySegment& segment) { segments_.push_back(segment); }

  // Check if address is valid within this binary
  bool IsValidAddress(uint32_t address) const;

  // Get byte at address (relative to load address)
  uint8_t GetByte(uint32_t address) const;

  // Get multiple bytes starting at address
  std::vector<uint8_t> GetBytes(uint32_t address, size_t count) const;

  // Get raw pointer to data at address (for performance)
  const uint8_t* GetPointer(uint32_t address) const;

 private:
  std::vector<uint8_t> data_;
  uint32_t load_address_;
  std::string source_file_;
  std::string file_type_;  // "DOS3.3", "PRODOS", "RAW", "COCO_LOADM", etc.

  // Multi-segment support (for CoCo LOADM format)
  std::vector<BinarySegment> segments_;
  uint32_t entry_point_ = 0;  // Execution address from postamble
};

}  // namespace core
}  // namespace sourcerer

#endif  // SOURCERER_CORE_BINARY_H_
