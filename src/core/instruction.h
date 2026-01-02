// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_CORE_INSTRUCTION_H_
#define SOURCERER_CORE_INSTRUCTION_H_

#include <cstdint>
#include <string>
#include <vector>

namespace sourcerer {
namespace core {

// CPU-specific addressing modes (extensible enum)
enum class AddressingMode {
  UNKNOWN = 0,
  // 6502 family modes
  IMPLIED,           // RTS
  ACCUMULATOR,       // ASL A
  IMMEDIATE,         // LDA #$FF
  ZERO_PAGE,         // LDA $00
  ZERO_PAGE_X,       // LDA $00,X
  ZERO_PAGE_Y,       // LDX $00,Y
  ABSOLUTE,          // LDA $1234
  ABSOLUTE_X,        // LDA $1234,X
  ABSOLUTE_Y,        // LDA $1234,Y
  INDIRECT,          // JMP ($1234)
  INDEXED_INDIRECT,  // LDA ($00,X)
  INDIRECT_INDEXED,  // LDA ($00),Y
  RELATIVE,          // BNE label
  ABSOLUTE_INDEXED_INDIRECT,  // JMP ($1234,X) - 65C02
  // 65816 additional modes
  ABSOLUTE_LONG,           // LDA $123456
  ABSOLUTE_LONG_X,         // LDA $123456,X
  STACK_RELATIVE,          // LDA $12,S
  STACK_RELATIVE_INDIRECT_INDEXED,  // LDA ($12,S),Y
  ABSOLUTE_INDIRECT_LONG,  // JMP [$1234]
  BLOCK_MOVE,              // MVN $12,$34
  // 6809 modes (future)
  DIRECT,
  EXTENDED,
  INDEXED,
  // Z80 modes (future)
  REGISTER,
  REGISTER_INDIRECT,
};

// Generic instruction representation
struct Instruction {
  uint32_t address;               // Location in memory
  std::vector<uint8_t> bytes;     // Raw bytes
  std::string mnemonic;           // e.g., "LDA"
  std::string operand;            // e.g., "#$FF"
  AddressingMode mode;            // Addressing mode
  uint32_t target_address;        // For branches/jumps (0 if N/A)
  bool is_branch;                 // Branch instruction
  bool is_jump;                   // Jump instruction
  bool is_call;                   // Subroutine call (JSR, etc.)
  bool is_return;                 // Return from subroutine (RTS, RTI, etc.)
  bool is_illegal;                // Illegal/undocumented opcode
  std::string comment;            // Optional comment

  Instruction();

  // Get instruction size
  size_t Size() const { return bytes.size(); }

  // Check if instruction has a target address
  bool HasTarget() const { return target_address != 0; }

  // Format instruction as string (mnemonic + operand)
  std::string ToString() const;
};

}  // namespace core
}  // namespace sourcerer

#endif  // SOURCERER_CORE_INSTRUCTION_H_
