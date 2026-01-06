// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "core/binary.h"

#include <fstream>
#include <stdexcept>
#include <iostream>

namespace sourcerer {
namespace core {

namespace {
// Helper to detect and parse CoCo LOADM format
// Returns true if successfully parsed as LOADM format
bool ParseCoCoLOADM(const std::vector<uint8_t>& data, Binary* binary) {
  if (data.size() < 10) {  // Minimum: 5-byte preamble + 5-byte postamble
    return false;
  }

  // Check for preamble signature (flag = $00)
  if (data[0] != 0x00) {
    return false;  // Not CoCo LOADM format
  }

  std::cout << "[INFO] Detected CoCo LOADM format" << std::endl;

  size_t offset = 0;
  int segment_num = 0;

  while (offset + 5 <= data.size()) {
    uint8_t flag = data[offset];
    uint16_t length = (static_cast<uint16_t>(data[offset + 1]) << 8) |
                      data[offset + 2];
    uint16_t address = (static_cast<uint16_t>(data[offset + 3]) << 8) |
                       data[offset + 4];

    if (flag == 0xFF) {
      // Postamble - marks end of file and execution address
      binary->set_entry_point(address);
      std::cout << "[INFO] Execution address: $" << std::hex << std::uppercase
                << address << std::dec << std::endl;
      break;
    } else if (flag == 0x00) {
      // Preamble - marks start of data segment
      segment_num++;
      offset += 5;  // Skip preamble

      if (offset + length > data.size()) {
        std::cerr << "[ERROR] Segment " << segment_num
                  << " extends beyond file" << std::endl;
        return false;
      }

      // Extract segment data
      BinarySegment segment;
      segment.load_address = address;
      segment.data.assign(data.begin() + offset, data.begin() + offset + length);

      binary->add_segment(segment);

      std::cout << "[INFO] Segment " << segment_num << ": $" << std::hex
                << std::uppercase << address << "-$"
                << (address + length - 1) << " (" << std::dec << length
                << " bytes)" << std::endl;

      offset += length;
    } else {
      std::cerr << "[ERROR] Unknown flag $" << std::hex << static_cast<int>(flag)
                << " at offset " << std::dec << offset << std::endl;
      return false;
    }
  }

  if (segment_num == 0) {
    std::cerr << "[ERROR] No segments found in LOADM file" << std::endl;
    return false;
  }

  binary->set_file_type("COCO_LOADM");
  return true;
}
}  // namespace

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

  // Try to parse as CoCo LOADM format first
  Binary binary;
  binary.set_source_file(path);

  if (ParseCoCoLOADM(buffer, &binary)) {
    // Successfully parsed as LOADM format
    // For backward compatibility, also populate data_ with first segment
    if (!binary.segments().empty()) {
      const auto& first_seg = binary.segments()[0];
      binary.data_ = first_seg.data;
      binary.load_address_ = first_seg.load_address;
    }
    return binary;
  }

  // Not LOADM format - treat as flat binary
  std::cout << "[INFO] Loading as flat binary at $" << std::hex << std::uppercase
            << load_address << std::dec << std::endl;
  binary.data_ = buffer;
  binary.load_address_ = load_address;
  binary.set_file_type("RAW");

  return binary;
}

bool Binary::IsValidAddress(uint32_t address) const {
  // For multi-segment binaries, check all segments
  if (is_multi_segment()) {
    for (const auto& segment : segments_) {
      if (address >= segment.load_address && address < segment.end_address()) {
        return true;
      }
    }
    return false;
  }

  // Single-segment (flat) binary
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

  // For multi-segment binaries, find the right segment
  if (is_multi_segment()) {
    for (const auto& segment : segments_) {
      if (address >= segment.load_address && address < segment.end_address()) {
        uint32_t offset = address - segment.load_address;
        return segment.data[offset];
      }
    }
    throw std::out_of_range("Address not found in any segment");
  }

  // Single-segment (flat) binary
  uint32_t offset = address - load_address_;
  return data_[offset];
}

std::vector<uint8_t> Binary::GetBytes(uint32_t address, size_t count) const {
  if (!IsValidAddress(address)) {
    return std::vector<uint8_t>();  // Return empty vector for invalid address
  }

  // For multi-segment binaries, find the right segment
  if (is_multi_segment()) {
    for (const auto& segment : segments_) {
      if (address >= segment.load_address && address < segment.end_address()) {
        uint32_t offset = address - segment.load_address;
        size_t available = segment.data.size() - offset;
        size_t actual_count = (count > available) ? available : count;

        std::vector<uint8_t> result(actual_count);
        for (size_t i = 0; i < actual_count; ++i) {
          result[i] = segment.data[offset + i];
        }
        return result;
      }
    }
    return std::vector<uint8_t>();
  }

  // Single-segment (flat) binary
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

  // For multi-segment binaries, find the right segment
  if (is_multi_segment()) {
    for (const auto& segment : segments_) {
      if (address >= segment.load_address && address < segment.end_address()) {
        uint32_t offset = address - segment.load_address;
        return segment.data.data() + offset;
      }
    }
    return nullptr;
  }

  // Single-segment (flat) binary
  uint32_t offset = address - load_address_;
  return data_.data() + offset;
}

}  // namespace core
}  // namespace sourcerer
