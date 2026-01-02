// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_CPU_M6502_OPCODES_6502_H_
#define SOURCERER_CPU_M6502_OPCODES_6502_H_

#include <cstdint>

#include "core/instruction.h"

namespace sourcerer {
namespace cpu {
namespace m6502 {

// Opcode information structure
struct OpcodeInfo {
  uint8_t opcode;
  const char* mnemonic;
  core::AddressingMode mode;
  uint8_t size;        // Instruction size in bytes
  uint8_t cycles;      // Base clock cycles
  bool is_branch;      // Branch instruction
  bool is_jump;        // Jump instruction (JMP)
  bool is_call;        // Subroutine call (JSR)
  bool is_return;      // Return from subroutine (RTS, RTI)
  bool is_illegal;     // Illegal/undocumented opcode
  bool is_65c02_only;  // Only available on 65C02
};

// 6502 opcode table (256 entries, one per opcode)
extern const OpcodeInfo OPCODE_TABLE_6502[256];

// Helper function to get opcode info
const OpcodeInfo& GetOpcodeInfo(uint8_t opcode);

// Check if opcode is valid for variant
bool IsValidOpcode(uint8_t opcode, bool allow_65c02 = false,
                   bool allow_illegal = false);

}  // namespace m6502
}  // namespace cpu
}  // namespace sourcerer

#endif  // SOURCERER_CPU_M6502_OPCODES_6502_H_
