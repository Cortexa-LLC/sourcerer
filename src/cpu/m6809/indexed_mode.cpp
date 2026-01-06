// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "cpu/m6809/indexed_mode.h"

#include <iomanip>
#include <sstream>

namespace sourcerer {
namespace cpu {
namespace m6809 {

// Helper to read 16-bit value (big-endian)
static uint16_t Read16BE(const uint8_t* data) {
  return (static_cast<uint16_t>(data[0]) << 8) | data[1];
}

// Helper to format signed 8-bit offset
static std::string FormatOffset8(int8_t offset) {
  std::ostringstream oss;
  if (offset >= 0) {
    oss << std::dec << static_cast<int>(offset);
  } else {
    oss << "-" << std::dec << static_cast<int>(-offset);
  }
  return oss.str();
}

// Helper to format signed 16-bit offset
static std::string FormatOffset16(int16_t offset) {
  std::ostringstream oss;
  if (offset >= 0) {
    oss << std::dec << static_cast<int>(offset);
  } else {
    oss << "-" << std::dec << static_cast<int>(-offset);
  }
  return oss.str();
}

IndexedModeResult ParseIndexedMode(const uint8_t* data, size_t size,
                                   uint32_t pc, size_t opcode_length) {
  IndexedModeResult result;
  result.size = 0;
  result.target_address = 0;
  result.is_indirect = false;
  result.is_valid = false;

  if (size == 0) {
    result.operand = "???";
    return result;
  }

  uint8_t postbyte = data[0];
  result.is_valid = true;

  // Bit 7 = 0: 5-bit offset mode (,R with 5-bit signed offset)
  if ((postbyte & 0x80) == 0) {
    // 5-bit signed offset (-16 to +15)
    int8_t offset = static_cast<int8_t>((postbyte & 0x1F) |
                                        ((postbyte & 0x10) ? 0xE0 : 0x00));

    // Register select (bits 6-5)
    const char* reg;
    switch ((postbyte >> 5) & 0x03) {
      case 0: reg = "X"; break;
      case 1: reg = "Y"; break;
      case 2: reg = "U"; break;
      case 3: reg = "S"; break;
      default: reg = "?"; break;
    }

    std::ostringstream oss;
    if (offset == 0) {
      oss << "," << reg;
    } else {
      oss << FormatOffset8(offset) << "," << reg;
    }
    result.operand = oss.str();
    result.size = 0;
    return result;
  }

  // Bit 7 = 1: Extended indexed modes
  bool indirect = (postbyte & 0x10) != 0;
  uint8_t reg_bits = (postbyte >> 5) & 0x03;
  uint8_t mode_bits = postbyte & 0x0F;

  const char* reg;
  switch (reg_bits) {
    case 0: reg = "X"; break;
    case 1: reg = "Y"; break;
    case 2: reg = "U"; break;
    case 3: reg = "S"; break;
    default: reg = "?"; break;
  }

  std::ostringstream oss;

  // Validate: indirect addressing with S register is illegal on 6809
  // Hardware does not support [,S+], [,S++], [,--S], [offset,S], etc.
  if (indirect && reg_bits == 3 && mode_bits != 0x0F) {
    // Exception: mode 0x0F is extended indirect [$xxxx], which doesn't use register
    result.operand = "[," + std::string(reg) + "]";  // Show what was attempted
    result.is_valid = false;
    return result;
  }

  // Decode mode
  switch (mode_bits) {
    case 0x00:  // ,R+
      oss << "," << reg << "+";
      break;

    case 0x01:  // ,R++
      oss << "," << reg << "++";
      break;

    case 0x02:  // ,-R
      oss << ",-" << reg;
      break;

    case 0x03:  // ,--R
      oss << ",--" << reg;
      break;

    case 0x04:  // ,R (no offset)
      oss << "," << reg;
      break;

    case 0x05:  // B,R (accumulator B offset)
      oss << "B," << reg;
      break;

    case 0x06:  // A,R (accumulator A offset)
      oss << "A," << reg;
      break;

    case 0x08:  // 8-bit offset,R
      if (size >= 2) {
        int8_t offset = static_cast<int8_t>(data[1]);
        oss << FormatOffset8(offset) << "," << reg;
        result.size = 1;
      } else {
        oss << "??," << reg;
        result.is_valid = false;
      }
      break;

    case 0x09:  // 16-bit offset,R
      if (size >= 3) {
        int16_t offset = static_cast<int16_t>(Read16BE(&data[1]));
        oss << FormatOffset16(offset) << "," << reg;
        result.size = 2;
      } else {
        oss << "??," << reg;
        result.is_valid = false;
      }
      break;

    case 0x0B:  // D,R (accumulator D offset)
      oss << "D," << reg;
      break;

    case 0x0C:  // 8-bit offset,PC
      if (size >= 2) {
        int8_t offset = static_cast<int8_t>(data[1]);
        // PC points to next instruction: opcode + postbyte + offset byte
        uint32_t pc_after = pc + opcode_length + 2;
        int32_t signed_target = static_cast<int32_t>(pc_after) + offset;

        // Validate: Target must be in valid 16-bit address space
        if (signed_target < 0 || signed_target > 0xFFFF) {
          result.is_valid = false;
          oss << FormatOffset8(offset) << ",PC";
          result.target_address = 0;
          result.size = 1;
        } else {
          result.target_address = static_cast<uint32_t>(signed_target);
          oss << FormatOffset8(offset) << ",PC";
          result.size = 1;
        }
      } else {
        oss << "??,PC";
        result.is_valid = false;
      }
      break;

    case 0x0D:  // 16-bit offset,PC
      if (size >= 3) {
        int16_t offset = static_cast<int16_t>(Read16BE(&data[1]));
        // PC points to next instruction: opcode + postbyte + offset bytes
        uint32_t pc_after = pc + opcode_length + 3;
        int32_t signed_target = static_cast<int32_t>(pc_after) + offset;

        // Validate: Target must be in valid 16-bit address space
        // Also check for extreme offsets that indicate DATA not CODE
        if (signed_target < 0 || signed_target > 0xFFFF ||
            offset < -32000 || offset > 32000) {
          result.is_valid = false;
          oss << FormatOffset16(offset) << ",PC";
          result.target_address = 0;
          result.size = 2;
        } else {
          result.target_address = static_cast<uint32_t>(signed_target);
          oss << FormatOffset16(offset) << ",PC";
          result.size = 2;
        }
      } else {
        oss << "??,PC";
        result.is_valid = false;
      }
      break;

    case 0x0F:  // Extended indirect (16-bit address)
      if (indirect && size >= 3) {
        uint16_t addr = Read16BE(&data[1]);
        oss << "[$" << std::hex << std::uppercase << std::setw(4)
            << std::setfill('0') << addr << "]";
        result.size = 2;
        result.target_address = addr;
      } else {
        oss << "[???]";
        result.is_valid = false;
      }
      break;

    default:
      oss << "???";
      result.is_valid = false;
      break;
  }

  // Wrap in brackets if indirect
  if (indirect && mode_bits != 0x0F) {
    result.operand = "[" + oss.str() + "]";
    result.is_indirect = true;
  } else {
    result.operand = oss.str();
    result.is_indirect = (mode_bits == 0x0F);
  }

  return result;
}

}  // namespace m6809
}  // namespace cpu
}  // namespace sourcerer
