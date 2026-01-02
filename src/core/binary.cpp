// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "core/binary.h"

#include <fstream>
#include <stdexcept>

namespace sourcerer {
namespace core {

Binary::Binary() : load_address_(0) {}

Binary::Binary(const std::vector<uint8_t>& data, uint32_t load_address)
    : data_(data), load_address_(load_address), file_type_("RAW") {}

Binary Binary::LoadFromFile(const std::string& path, uint32_t load_address) {
  std::ifstream file(path, std::ios::binary | std::ios::ate);
  if (!file.is_open()) {
    throw std::runtime_error("Failed to open file: " + path);
  }

  std::streamsize size = file.tellg();
  file.seekg(0, std::ios::beg);

  std::vector<uint8_t> buffer(size);
  if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
    throw std::runtime_error("Failed to read file: " + path);
  }

  Binary binary(buffer, load_address);
  binary.set_source_file(path);
  return binary;
}

bool Binary::IsValidAddress(uint32_t address) const {
  if (address < load_address_) {
    return false;
  }
  uint32_t offset = address - load_address_;
  return offset < data_.size();
}

uint8_t Binary::GetByte(uint32_t address) const {
  if (!IsValidAddress(address)) {
    throw std::out_of_range("Address out of range");
  }
  uint32_t offset = address - load_address_;
  return data_[offset];
}

std::vector<uint8_t> Binary::GetBytes(uint32_t address, size_t count) const {
  if (!IsValidAddress(address)) {
    return std::vector<uint8_t>();  // Return empty vector for invalid address
  }

  uint32_t offset = address - load_address_;
  size_t available = data_.size() - offset;
  size_t actual_count = (count > available) ? available : count;

  std::vector<uint8_t> result(actual_count);
  for (size_t i = 0; i < actual_count; ++i) {
    result[i] = data_[offset + i];
  }
  return result;
}

const uint8_t* Binary::GetPointer(uint32_t address) const {
  if (!IsValidAddress(address)) {
    return nullptr;
  }
  uint32_t offset = address - load_address_;
  return data_.data() + offset;
}

}  // namespace core
}  // namespace sourcerer
