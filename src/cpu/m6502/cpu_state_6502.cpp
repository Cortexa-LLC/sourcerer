// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "cpu/m6502/cpu_state_6502.h"

#include "core/instruction.h"
#include "utils/logger.h"

namespace sourcerer {
namespace cpu {

bool CpuState6502::EvaluateBranchCondition(const std::string& mnemonic) {
  // Evaluate 6502 branch conditions based on current status flags

  // Branch on carry
  if (mnemonic == "BCC") return !flag_C();  // Branch if carry clear
  if (mnemonic == "BCS") return flag_C();   // Branch if carry set

  // Branch on zero
  if (mnemonic == "BEQ") return flag_Z();   // Branch if equal (zero set)
  if (mnemonic == "BNE") return !flag_Z();  // Branch if not equal (zero clear)

  // Branch on negative
  if (mnemonic == "BMI") return flag_N();   // Branch if minus (negative set)
  if (mnemonic == "BPL") return !flag_N();  // Branch if plus (negative clear)

  // Branch on overflow
  if (mnemonic == "BVC") return !flag_V();  // Branch if overflow clear
  if (mnemonic == "BVS") return flag_V();   // Branch if overflow set

  // 65C02 additional branch instructions
  if (mnemonic == "BRA") return true;       // Branch always (65C02)

  // Unknown branch - assume not taken for safety
  LOG_WARNING("Unknown 6502 branch mnemonic: " + mnemonic);
  return false;
}

bool CpuState6502::ExecuteInstruction(const core::Instruction& inst,
                                       ReadMemoryCallback read,
                                       WriteMemoryCallback write) {
  // Suppress unused parameter warnings
  (void)read;
  (void)write;

  const std::string& mnem = inst.mnemonic;
  const auto& bytes = inst.bytes;
  bool is_immediate = (inst.mode == core::AddressingMode::IMMEDIATE);

  // Extract immediate operand if present
  uint8_t operand = 0;
  if (bytes.size() >= 2) {
    operand = bytes[1];
  }

  // Load instructions - focus on immediate mode for simplicity
  if (mnem == "LDA") {
    if (is_immediate) {
      A = operand;
      UpdateNZ(A);
    }
    // For non-immediate, we'd need address calculation - skip for now
    return true;
  }

  if (mnem == "LDX") {
    if (is_immediate) {
      X = operand;
      UpdateNZ(X);
    }
    return true;
  }

  if (mnem == "LDY") {
    if (is_immediate) {
      Y = operand;
      UpdateNZ(Y);
    }
    return true;
  }

  // Compare instructions - immediate mode only
  if (mnem == "CMP") {
    if (is_immediate) {
      uint16_t result = A - operand;
      set_flag_C(A >= operand);  // Carry set if A >= operand
      set_flag_Z((result & 0xFF) == 0);
      set_flag_N((result & 0x80) != 0);
    }
    return true;
  }

  if (mnem == "CPX") {
    if (is_immediate) {
      uint16_t result = X - operand;
      set_flag_C(X >= operand);
      set_flag_Z((result & 0xFF) == 0);
      set_flag_N((result & 0x80) != 0);
    }
    return true;
  }

  if (mnem == "CPY") {
    if (is_immediate) {
      uint16_t result = Y - operand;
      set_flag_C(Y >= operand);
      set_flag_Z((result & 0xFF) == 0);
      set_flag_N((result & 0x80) != 0);
    }
    return true;
  }

  // Arithmetic instructions - immediate mode only
  if (mnem == "ADC") {
    if (is_immediate) {
      uint16_t result = A + operand + (flag_C() ? 1 : 0);
      bool overflow = ((A ^ result) & (operand ^ result) & 0x80) != 0;
      A = result & 0xFF;
      set_flag_C(result > 0xFF);
      set_flag_V(overflow);
      UpdateNZ(A);
    }
    return true;
  }

  if (mnem == "SBC") {
    if (is_immediate) {
      uint16_t result = A - operand - (flag_C() ? 0 : 1);
      bool overflow = ((A ^ operand) & (A ^ result) & 0x80) != 0;
      A = result & 0xFF;
      set_flag_C(result < 0x100);
      set_flag_V(overflow);
      UpdateNZ(A);
    }
    return true;
  }

  // Logical instructions - immediate mode only
  if (mnem == "AND") {
    if (is_immediate) {
      A &= operand;
      UpdateNZ(A);
    }
    return true;
  }

  if (mnem == "ORA") {
    if (is_immediate) {
      A |= operand;
      UpdateNZ(A);
    }
    return true;
  }

  if (mnem == "EOR") {
    if (is_immediate) {
      A ^= operand;
      UpdateNZ(A);
    }
    return true;
  }

  if (mnem == "INX") {
    X++;
    UpdateNZ(X);
    return true;
  }

  if (mnem == "DEX") {
    X--;
    UpdateNZ(X);
    return true;
  }

  if (mnem == "INY") {
    Y++;
    UpdateNZ(Y);
    return true;
  }

  if (mnem == "DEY") {
    Y--;
    UpdateNZ(Y);
    return true;
  }

  // Flag manipulation
  if (mnem == "SEC") {
    set_flag_C(true);
    return true;
  }

  if (mnem == "CLC") {
    set_flag_C(false);
    return true;
  }

  if (mnem == "SEI") {
    set_flag_I(true);
    return true;
  }

  if (mnem == "CLI") {
    set_flag_I(false);
    return true;
  }

  if (mnem == "SED") {
    set_flag_D(true);
    return true;
  }

  if (mnem == "CLD") {
    set_flag_D(false);
    return true;
  }

  if (mnem == "CLV") {
    set_flag_V(false);
    return true;
  }

  // Transfer instructions
  if (mnem == "TAX") {
    X = A;
    UpdateNZ(X);
    return true;
  }

  if (mnem == "TAY") {
    Y = A;
    UpdateNZ(Y);
    return true;
  }

  if (mnem == "TXA") {
    A = X;
    UpdateNZ(A);
    return true;
  }

  if (mnem == "TYA") {
    A = Y;
    UpdateNZ(A);
    return true;
  }

  if (mnem == "TSX") {
    X = SP;
    UpdateNZ(X);
    return true;
  }

  if (mnem == "TXS") {
    SP = X;
    // TXS does not affect flags
    return true;
  }

  // NOP
  if (mnem == "NOP") {
    return true;
  }

  // For any unimplemented instruction, just continue simulation
  // Control flow instructions (branches, jumps, calls, returns) are handled
  // by ExecutionSimulator itself, not here
  return true;
}

}  // namespace cpu
}  // namespace sourcerer
