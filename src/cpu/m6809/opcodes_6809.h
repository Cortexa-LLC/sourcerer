// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_CPU_M6809_OPCODES_6809_H_
#define SOURCERER_CPU_M6809_OPCODES_6809_H_

#include <cstdint>

#include "core/instruction.h"

namespace sourcerer {
namespace cpu {
namespace m6809 {

// Opcode information structure for 6809
struct OpcodeInfo6809 {
  uint8_t opcode;
  const char* mnemonic;  // nullptr for illegal opcodes
  core::AddressingMode mode;
  uint8_t size;        // Base instruction size in bytes (may be extended by indexed mode)
  uint8_t cycles;      // Base clock cycles
  bool is_branch;      // Branch instruction
  bool is_jump;        // Jump instruction (JMP)
  bool is_call;        // Subroutine call (JSR, BSR, LBSR)
  bool is_return;      // Return from subroutine (RTS, RTI)
  bool is_page2;       // Page 2 instruction ($10 prefix)
  bool is_page3;       // Page 3 instruction ($11 prefix)
  bool is_illegal;     // Illegal/undefined opcode
};

// 6809 opcode tables
extern const OpcodeInfo6809 OPCODE_TABLE_6809[256];       // Main page
extern const OpcodeInfo6809 OPCODE_TABLE_6809_PAGE2[256]; // Page 2 ($10 prefix)
extern const OpcodeInfo6809 OPCODE_TABLE_6809_PAGE3[256]; // Page 3 ($11 prefix)

// Helper function to get opcode info (handles page prefixes)
const OpcodeInfo6809& GetOpcodeInfo(const uint8_t* data, size_t size,
                                    size_t* bytes_consumed = nullptr);

// Check if opcode is valid
bool IsValidOpcode(const uint8_t* data, size_t size);

}  // namespace m6809
}  // namespace cpu
}  // namespace sourcerer

#endif  // SOURCERER_CPU_M6809_OPCODES_6809_H_
