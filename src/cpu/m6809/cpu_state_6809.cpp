// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "cpu/m6809/cpu_state_6809.h"

#include "core/instruction.h"
#include "utils/logger.h"

namespace sourcerer {
namespace cpu {

bool CpuState6809::EvaluateBranchCondition(const std::string& mnemonic) {
  // Evaluate 6809 branch conditions based on current CC flags
  if (mnemonic == "BRA" || mnemonic == "LBRA") return true;  // Always

  if (mnemonic == "BEQ" || mnemonic == "LBEQ") return flag_Z();
  if (mnemonic == "BNE" || mnemonic == "LBNE") return !flag_Z();

  if (mnemonic == "BMI" || mnemonic == "LBMI") return flag_N();
  if (mnemonic == "BPL" || mnemonic == "LBPL") return !flag_N();

  if (mnemonic == "BCS" || mnemonic == "BLO" || mnemonic == "LBCS" || mnemonic == "LBLO")
    return flag_C();
  if (mnemonic == "BCC" || mnemonic == "BHS" || mnemonic == "LBCC" || mnemonic == "LBHS")
    return !flag_C();

  if (mnemonic == "BVS" || mnemonic == "LBVS") return flag_V();
  if (mnemonic == "BVC" || mnemonic == "LBVC") return !flag_V();

  // Signed comparisons
  if (mnemonic == "BGT" || mnemonic == "LBGT")
    return !flag_Z() && (flag_N() == flag_V());
  if (mnemonic == "BGE" || mnemonic == "LBGE")
    return (flag_N() == flag_V());
  if (mnemonic == "BLT" || mnemonic == "LBLT")
    return (flag_N() != flag_V());
  if (mnemonic == "BLE" || mnemonic == "LBLE")
    return flag_Z() || (flag_N() != flag_V());

  // Unsigned comparisons
  if (mnemonic == "BHI" || mnemonic == "LBHI")
    return !flag_C() && !flag_Z();
  if (mnemonic == "BLS" || mnemonic == "LBLS")
    return flag_C() || flag_Z();

  // Unknown branch - assume not taken for safety
  LOG_WARNING("Unknown 6809 branch mnemonic: " + mnemonic);
  return false;
}

bool CpuState6809::ExecuteInstruction(const core::Instruction& inst,
                                       ReadMemoryCallback read,
                                       WriteMemoryCallback write) {
  // Suppress unused parameter warnings
  (void)read;
  (void)write;

  const std::string& mnem = inst.mnemonic;
  const auto& bytes = inst.bytes;
  bool is_immediate = (inst.mode == core::AddressingMode::IMMEDIATE);

  // Extract immediate operand if present
  uint8_t operand8 = 0;
  uint16_t operand16 = 0;
  if (bytes.size() >= 2) {
    operand8 = bytes[1];
  }
  if (bytes.size() >= 3) {
    operand16 = (static_cast<uint16_t>(bytes[1]) << 8) | bytes[2];
  }

  // 8-bit Load instructions - immediate mode only
  if (mnem == "LDA" || mnem == "LDAA") {
    if (is_immediate) {
      A = operand8;
      UpdateNZ8(A);
      set_flag_V(false);
    }
    return true;
  }

  if (mnem == "LDB" || mnem == "LDAB") {
    if (is_immediate) {
      B = operand8;
      UpdateNZ8(B);
      set_flag_V(false);
    }
    return true;
  }

  // 16-bit Load instructions - immediate mode only
  if (mnem == "LDD") {
    if (is_immediate) {
      set_D(operand16);
      UpdateNZ16(D());
      set_flag_V(false);
    }
    return true;
  }

  if (mnem == "LDX") {
    if (is_immediate) {
      X = operand16;
      UpdateNZ16(X);
      set_flag_V(false);
    }
    return true;
  }

  if (mnem == "LDY") {
    if (is_immediate) {
      Y = operand16;
      UpdateNZ16(Y);
      set_flag_V(false);
    }
    return true;
  }

  if (mnem == "LDU") {
    if (is_immediate) {
      U = operand16;
      UpdateNZ16(U);
      set_flag_V(false);
    }
    return true;
  }

  if (mnem == "LDS") {
    if (is_immediate) {
      S = operand16;
      UpdateNZ16(S);
      set_flag_V(false);
    }
    return true;
  }

  // Compare instructions - immediate mode only
  if (mnem == "CMPA") {
    if (is_immediate) {
      uint16_t result = A - operand8;
      set_flag_C(A < operand8);  // Borrow (inverse of 6502)
      set_flag_Z((result & 0xFF) == 0);
      set_flag_N((result & 0x80) != 0);
      set_flag_V(((A ^ operand8) & (A ^ result) & 0x80) != 0);
    }
    return true;
  }

  if (mnem == "CMPB") {
    if (is_immediate) {
      uint16_t result = B - operand8;
      set_flag_C(B < operand8);
      set_flag_Z((result & 0xFF) == 0);
      set_flag_N((result & 0x80) != 0);
      set_flag_V(((B ^ operand8) & (B ^ result) & 0x80) != 0);
    }
    return true;
  }

  if (mnem == "CMPD") {
    if (is_immediate) {
      uint32_t result = D() - operand16;
      set_flag_C(D() < operand16);
      set_flag_Z((result & 0xFFFF) == 0);
      set_flag_N((result & 0x8000) != 0);
      set_flag_V(((D() ^ operand16) & (D() ^ result) & 0x8000) != 0);
    }
    return true;
  }

  if (mnem == "CMPX") {
    if (is_immediate) {
      uint32_t result = X - operand16;
      set_flag_C(X < operand16);
      set_flag_Z((result & 0xFFFF) == 0);
      set_flag_N((result & 0x8000) != 0);
      set_flag_V(((X ^ operand16) & (X ^ result) & 0x8000) != 0);
    }
    return true;
  }

  if (mnem == "CMPY") {
    if (is_immediate) {
      uint32_t result = Y - operand16;
      set_flag_C(Y < operand16);
      set_flag_Z((result & 0xFFFF) == 0);
      set_flag_N((result & 0x8000) != 0);
      set_flag_V(((Y ^ operand16) & (Y ^ result) & 0x8000) != 0);
    }
    return true;
  }

  // Arithmetic instructions - immediate mode only
  if (mnem == "ADDA") {
    if (is_immediate) {
      uint16_t result = A + operand8;
      bool halfCarry = ((A & 0x0F) + (operand8 & 0x0F)) > 0x0F;
      bool overflow = ((A ^ result) & (operand8 ^ result) & 0x80) != 0;
      A = result & 0xFF;
      set_flag_C(result > 0xFF);
      set_flag_V(overflow);
      UpdateNZ8(A);
      if (halfCarry) CC |= 0x20;  // Set H flag
    }
    return true;
  }

  if (mnem == "ADDB") {
    if (is_immediate) {
      uint16_t result = B + operand8;
      bool halfCarry = ((B & 0x0F) + (operand8 & 0x0F)) > 0x0F;
      bool overflow = ((B ^ result) & (operand8 ^ result) & 0x80) != 0;
      B = result & 0xFF;
      set_flag_C(result > 0xFF);
      set_flag_V(overflow);
      UpdateNZ8(B);
      if (halfCarry) CC |= 0x20;  // Set H flag
    }
    return true;
  }

  if (mnem == "ADDD") {
    if (is_immediate) {
      uint32_t result = D() + operand16;
      bool overflow = ((D() ^ result) & (operand16 ^ result) & 0x8000) != 0;
      set_D(result & 0xFFFF);
      set_flag_C(result > 0xFFFF);
      set_flag_V(overflow);
      UpdateNZ16(D());
    }
    return true;
  }

  if (mnem == "SUBA") {
    if (is_immediate) {
      uint16_t result = A - operand8;
      bool overflow = ((A ^ operand8) & (A ^ result) & 0x80) != 0;
      A = result & 0xFF;
      set_flag_C(result > 0xFF);  // Borrow
      set_flag_V(overflow);
      UpdateNZ8(A);
    }
    return true;
  }

  if (mnem == "SUBB") {
    if (is_immediate) {
      uint16_t result = B - operand8;
      bool overflow = ((B ^ operand8) & (B ^ result) & 0x80) != 0;
      B = result & 0xFF;
      set_flag_C(result > 0xFF);  // Borrow
      set_flag_V(overflow);
      UpdateNZ8(B);
    }
    return true;
  }

  if (mnem == "SUBD") {
    if (is_immediate) {
      uint32_t result = D() - operand16;
      bool overflow = ((D() ^ operand16) & (D() ^ result) & 0x8000) != 0;
      set_D(result & 0xFFFF);
      set_flag_C(result > 0xFFFF);  // Borrow
      set_flag_V(overflow);
      UpdateNZ16(D());
    }
    return true;
  }

  // Logical instructions - immediate mode only
  if (mnem == "ANDA") {
    if (is_immediate) {
      A &= operand8;
      UpdateNZ8(A);
      set_flag_V(false);
    }
    return true;
  }

  if (mnem == "ANDB") {
    if (is_immediate) {
      B &= operand8;
      UpdateNZ8(B);
      set_flag_V(false);
    }
    return true;
  }

  if (mnem == "ORA" || mnem == "ORAA") {
    if (is_immediate) {
      A |= operand8;
      UpdateNZ8(A);
      set_flag_V(false);
    }
    return true;
  }

  if (mnem == "ORB" || mnem == "ORAB") {
    if (is_immediate) {
      B |= operand8;
      UpdateNZ8(B);
      set_flag_V(false);
    }
    return true;
  }

  if (mnem == "EORA") {
    if (is_immediate) {
      A ^= operand8;
      UpdateNZ8(A);
      set_flag_V(false);
    }
    return true;
  }

  if (mnem == "EORB") {
    if (is_immediate) {
      B ^= operand8;
      UpdateNZ8(B);
      set_flag_V(false);
    }
    return true;
  }

  // Increment/Decrement
  if (mnem == "INCA") {
    A++;
    UpdateNZ8(A);
    set_flag_V(A == 0x80);  // Overflow if result is $80
    return true;
  }

  if (mnem == "INCB") {
    B++;
    UpdateNZ8(B);
    set_flag_V(B == 0x80);
    return true;
  }

  if (mnem == "DECA") {
    A--;
    UpdateNZ8(A);
    set_flag_V(A == 0x7F);  // Overflow if result is $7F
    return true;
  }

  if (mnem == "DECB") {
    B--;
    UpdateNZ8(B);
    set_flag_V(B == 0x7F);
    return true;
  }

  // Test instructions
  if (mnem == "TSTA") {
    UpdateNZ8(A);
    set_flag_V(false);
    return true;
  }

  if (mnem == "TSTB") {
    UpdateNZ8(B);
    set_flag_V(false);
    return true;
  }

  // Transfer instructions
  if (mnem == "TFR") {
    // Would need to parse source/dest registers from postbyte
    // For now, just continue
    return true;
  }

  if (mnem == "EXG") {
    // Would need to parse registers from postbyte
    return true;
  }

  // Clear/Set flag instructions
  if (mnem == "ANDCC") {
    CC &= operand8;
    return true;
  }

  if (mnem == "ORCC") {
    CC |= operand8;
    return true;
  }

  // Stack operations
  if (mnem == "PSHS" || mnem == "PSHU" || mnem == "PULS" || mnem == "PULU") {
    // Would need stack tracking
    return true;
  }

  // NOP
  if (mnem == "NOP") {
    return true;
  }

  // LEA instructions (load effective address)
  if (mnem == "LEAX" || mnem == "LEAY" || mnem == "LEAU" || mnem == "LEAS") {
    // These set Z flag but we'd need indexed addressing resolution
    // For now, just continue
    return true;
  }

  // For any unimplemented instruction, just continue simulation
  // Control flow instructions are handled by ExecutionSimulator
  return true;
}

}  // namespace cpu
}  // namespace sourcerer
