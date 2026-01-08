// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "output/address_analyzer.h"

namespace sourcerer {
namespace output {

std::set<uint32_t> AddressAnalyzer::CollectReferencedAddresses(
    const std::vector<core::Instruction>& instructions) const {

  std::set<uint32_t> referenced_addresses;

  if (!binary_) {
    return referenced_addresses;
  }

  // Collect from instruction target_address fields (branches/jumps)
  for (const auto& inst : instructions) {
    if (inst.target_address != 0) {
      referenced_addresses.insert(inst.target_address);
    }

    // Also extract addresses from zero page and absolute addressing modes
    // Parse addresses from operands like "$4E", "$0800", "#$28", etc.
    if (!inst.operand.empty()) {
      std::string operand = inst.operand;
      // Handle both immediate (#$XX) and direct ($XX) modes
      size_t dollar_pos = operand.find('$');
      if (dollar_pos != std::string::npos && dollar_pos + 1 < operand.length()) {
        try {
          // Parse hex address from operand (skip past $)
          std::string addr_str = operand.substr(dollar_pos + 1);
          // Remove any trailing characters (like ,X or ,Y)
          size_t comma_pos = addr_str.find(',');
          if (comma_pos != std::string::npos) {
            addr_str = addr_str.substr(0, comma_pos);
          }
          uint32_t addr = std::stoul(addr_str, nullptr, 16);
          // Only add zero page ($00-$FF) and valid absolute addresses
          if (addr < 0x100 || (addr >= 0x0800 && addr < 0x10000)) {
            referenced_addresses.insert(addr);
          }
        } catch (...) {
          // Ignore parse errors
        }
      }
    }
  }

  // Scan data regions for address tables
  uint32_t scan_addr = binary_->load_address();
  uint32_t scan_end = scan_addr + binary_->size();
  while (scan_addr < scan_end) {
    if (address_map_ && address_map_->GetType(scan_addr) == core::AddressType::DATA) {
      // Check if this looks like an address pair
      const uint8_t* lo = binary_->GetPointer(scan_addr);
      const uint8_t* hi = binary_->GetPointer(scan_addr + 1);
      if (lo && hi) {
        uint16_t potential_addr = (*lo) | ((*hi) << 8);
        // If it looks like a valid address, add it
        if (potential_addr >= 0x0800 || potential_addr < 0x0100) {
          referenced_addresses.insert(potential_addr);
        }
      }
      scan_addr++;
    } else {
      scan_addr++;
    }
  }

  return referenced_addresses;
}

bool AddressAnalyzer::LooksLikeAddress(uint16_t addr) const {
  // Zero page addresses are valid (common on 6502)
  if (addr < 0x0100) {
    return true;
  }

  // ROM addresses are valid (Apple II, CoCo)
  if (addr >= 0xC000) {
    return true;
  }

  // Check if within binary range
  if (binary_ && binary_->IsValidAddress(addr)) {
    return true;
  }

  // Check if known in address map
  if (address_map_ && (address_map_->IsCode(addr) || address_map_->IsData(addr))) {
    return true;
  }

  // Common load addresses
  if (addr >= 0x0400) {
    return true;
  }

  return false;
}

AddressTableInfo AddressAnalyzer::FindAddressTableLengthAndOffset(
    const std::vector<uint8_t>& bytes) const {

  AddressTableInfo info;
  info.length = 0;
  info.offset = 0;
  info.is_valid = false;

  if (bytes.size() < 4) {
    return info;
  }

  // Try starting at offset 0
  size_t valid_length_0 = 0;
  for (size_t i = 0; i + 1 < bytes.size(); i += 2) {
    uint16_t addr = bytes[i] | (bytes[i + 1] << 8);
    if (LooksLikeAddress(addr)) {
      valid_length_0 += 2;
    } else {
      break;
    }
  }

  // Try starting at offset 1 (skip first byte)
  size_t valid_length_1 = 0;
  if (bytes.size() >= 5) {
    for (size_t i = 1; i + 1 < bytes.size(); i += 2) {
      uint16_t addr = bytes[i] | (bytes[i + 1] << 8);
      if (LooksLikeAddress(addr)) {
        valid_length_1 += 2;
      } else {
        break;
      }
    }
  }

  // Prefer offset 1 if it gives longer table or first byte is control char
  bool prefer_offset_1 = false;
  if (valid_length_1 > valid_length_0) {
    prefer_offset_1 = true;
  } else if (valid_length_1 == valid_length_0 && valid_length_0 >= 4) {
    // Check first address from each offset
    uint16_t addr0 = bytes[0] | (bytes[1] << 8);
    uint16_t addr1 = bytes[1] | (bytes[2] << 8);

    // Prefer offset 1 if it gives higher/more typical addresses
    if (addr1 >= 0x0400 && addr0 < 0x0400) {
      prefer_offset_1 = true;
    }
    // Or if first byte is control/graphics char
    else if (bytes[0] < 0x20 && bytes[0] != 0x00) {
      prefer_offset_1 = true;
    }
  }

  if (prefer_offset_1 && valid_length_1 >= 4) {
    info.length = valid_length_1;
    info.offset = 1;
    info.is_valid = true;
  } else if (valid_length_0 >= 4) {
    info.length = valid_length_0;
    info.offset = 0;
    info.is_valid = true;
  }

  return info;
}

}  // namespace output
}  // namespace sourcerer
