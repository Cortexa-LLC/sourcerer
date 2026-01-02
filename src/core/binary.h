// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_CORE_BINARY_H_
#define SOURCERER_CORE_BINARY_H_

#include <cstdint>
#include <string>
#include <vector>

namespace sourcerer {
namespace core {

// Represents a binary program loaded into memory
class Binary {
 public:
  Binary();
  Binary(const std::vector<uint8_t>& data, uint32_t load_address);

  // Load binary from file
  static Binary LoadFromFile(const std::string& path, uint32_t load_address);

  // Accessors
  const std::vector<uint8_t>& data() const { return data_; }
  uint32_t load_address() const { return load_address_; }
  uint32_t size() const { return static_cast<uint32_t>(data_.size()); }
  const std::string& source_file() const { return source_file_; }
  const std::string& file_type() const { return file_type_; }

  // Mutators
  void set_load_address(uint32_t address) { load_address_ = address; }
  void set_source_file(const std::string& file) { source_file_ = file; }
  void set_file_type(const std::string& type) { file_type_ = type; }

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
  std::string file_type_;  // "DOS3.3", "PRODOS", "RAW", etc.
};

}  // namespace core
}  // namespace sourcerer

#endif  // SOURCERER_CORE_BINARY_H_
