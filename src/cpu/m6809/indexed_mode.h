// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_CPU_M6809_INDEXED_MODE_H_
#define SOURCERER_CPU_M6809_INDEXED_MODE_H_

#include <cstdint>
#include <string>

namespace sourcerer {
namespace cpu {
namespace m6809 {

// Result of parsing 6809 indexed addressing mode
struct IndexedModeResult {
  std::string operand;      // Formatted operand string (e.g., "10,X" or "[,S++]")
  uint8_t size;             // Additional bytes consumed beyond post-byte (0-2)
  uint32_t target_address;  // For PC-relative modes (0 if not applicable)
  bool is_indirect;         // True if using indirect addressing
  bool is_valid;            // True if post-byte was successfully parsed
};

// Parse 6809 indexed addressing mode post-byte
// data: pointer to post-byte (byte after opcode)
// size: remaining bytes available
// pc: current program counter (address of opcode)
// opcode_length: length of opcode in bytes (1 or 2)
IndexedModeResult ParseIndexedMode(const uint8_t* data, size_t size,
                                   uint32_t pc, size_t opcode_length);

}  // namespace m6809
}  // namespace cpu
}  // namespace sourcerer

#endif  // SOURCERER_CPU_M6809_INDEXED_MODE_H_
