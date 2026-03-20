// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "analysis/llm/code_pattern_detector.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

#include "utils/logger.h"

namespace sourcerer {
namespace analysis {
namespace llm {

namespace {

// Case-insensitive mnemonic equality check.
bool Mnemonic(const core::Instruction& inst, const char* m) {
  return inst.mnemonic == m;
}

// Check if the instruction's mnemonic is in a set.
bool MnemonicIn(const core::Instruction& inst,
                const std::initializer_list<const char*>& mnemonics) {
  for (const char* m : mnemonics) {
    if (inst.mnemonic == m) return true;
  }
  return false;
}

// Check for ISR prologue: PHP/PHA at the start (within first 4 instructions).
bool HasIsrPrologue(const std::vector<core::Instruction>& insns) {
  int php_count = 0, pha_count = 0;
  for (size_t i = 0; i < insns.size() && i < 4; ++i) {
    if (Mnemonic(insns[i], "PHP")) ++php_count;
    if (Mnemonic(insns[i], "PHA")) ++pha_count;
  }
  return php_count >= 1 && pha_count >= 1;
}

// Check for ISR epilogue: RTI anywhere in the block.
bool HasIsrEpilogue(const std::vector<core::Instruction>& insns) {
  for (const auto& inst : insns) {
    if (Mnemonic(inst, "RTI")) return true;
  }
  return false;
}

// Detect string operations: inner loop LDA/STA/INX/BNE or LDA/CMP/BEQ/INX.
bool IsStringOp(const std::vector<core::Instruction>& insns) {
  int lda_count = 0, sta_count = 0, inx_count = 0, iny_count = 0;
  int bne_count = 0, cmp_count = 0, beq_count = 0;
  for (const auto& i : insns) {
    if (Mnemonic(i, "LDA")) ++lda_count;
    if (Mnemonic(i, "STA")) ++sta_count;
    if (Mnemonic(i, "INX")) ++inx_count;
    if (Mnemonic(i, "INY")) ++iny_count;
    if (Mnemonic(i, "BNE")) ++bne_count;
    if (Mnemonic(i, "CMP")) ++cmp_count;
    if (Mnemonic(i, "BEQ")) ++beq_count;
  }
  // Copy loop: LDA + STA + (INX|INY) + BNE
  bool copy_loop = lda_count >= 1 && sta_count >= 1
                   && (inx_count + iny_count) >= 1 && bne_count >= 1;
  // Compare / search loop: LDA + CMP + (BNE|BEQ) + (INX|INY)
  bool compare_loop = lda_count >= 1 && cmp_count >= 1
                      && (bne_count + beq_count) >= 1
                      && (inx_count + iny_count) >= 1;
  return copy_loop || compare_loop;
}

// Detect graphics routines: Apple II soft switch accesses ($C050-$C057)
// or tight LDA/STA loops over display memory range.
bool IsGraphicsRoutine(const std::vector<core::Instruction>& insns) {
  for (const auto& i : insns) {
    // Apple II soft-switch addresses for HIRES/LORES
    if (MnemonicIn(i, {"STA", "LDA"}) &&
        i.target_address >= 0xC050 && i.target_address <= 0xC057) {
      return true;
    }
    // Screen-clear-style tight loop accessing $0400-$07FF (LORES) or
    // $2000-$3FFF (HIRES page 1)
    if (MnemonicIn(i, {"STA"}) &&
        ((i.target_address >= 0x0400 && i.target_address <= 0x07FF) ||
         (i.target_address >= 0x2000 && i.target_address <= 0x3FFF))) {
      return true;
    }
  }
  return false;
}

// Detect math routines: shift-and-add loops, BCD (SED/CLD), 16-bit ops.
bool IsMathRoutine(const std::vector<core::Instruction>& insns) {
  int sed_count = 0;
  int asl_count = 0, lsr_count = 0, rol_count = 0, ror_count = 0;
  int adc_count = 0, sbc_count = 0;
  for (const auto& i : insns) {
    if (Mnemonic(i, "SED")) ++sed_count;
    if (Mnemonic(i, "ASL")) ++asl_count;
    if (Mnemonic(i, "LSR")) ++lsr_count;
    if (Mnemonic(i, "ROL")) ++rol_count;
    if (Mnemonic(i, "ROR")) ++ror_count;
    if (Mnemonic(i, "ADC")) ++adc_count;
    if (Mnemonic(i, "SBC")) ++sbc_count;
  }
  bool bcd = sed_count >= 1 && (adc_count >= 1 || sbc_count >= 1);
  bool shift_arith = (asl_count + lsr_count + rol_count + ror_count) >= 2
                     && (adc_count + sbc_count) >= 1;
  return bcd || shift_arith;
}

// Detect block memory operations: block move / clear / fill.
bool IsMemoryOp(const std::vector<core::Instruction>& insns) {
  int lda_count = 0, sta_count = 0, dex_count = 0, dey_count = 0;
  int bne_count = 0;
  bool has_mvn_mvp = false;
  for (const auto& i : insns) {
    if (Mnemonic(i, "LDA")) ++lda_count;
    if (Mnemonic(i, "STA")) ++sta_count;
    if (Mnemonic(i, "DEX")) ++dex_count;
    if (Mnemonic(i, "DEY")) ++dey_count;
    if (Mnemonic(i, "BNE")) ++bne_count;
    if (MnemonicIn(i, {"MVN", "MVP"})) has_mvn_mvp = true;
  }
  if (has_mvn_mvp) return true;
  // Block clear: LDA #0 / STA / DEX / BNE pattern
  bool block_clear = lda_count >= 1 && sta_count >= 1
                     && (dex_count + dey_count) >= 1 && bne_count >= 1;
  return block_clear;
}

// Detect I/O polling: keyboard ($C000/$C010) or wait loops.
bool IsIoPolling(const std::vector<core::Instruction>& insns) {
  int bpl_count = 0;
  for (const auto& i : insns) {
    // Apple II keyboard read $C000, strobe $C010
    if (Mnemonic(i, "LDA") &&
        (i.target_address == 0xC000 || i.target_address == 0xC010)) {
      return true;
    }
    if (Mnemonic(i, "BPL")) ++bpl_count;
  }
  // Generic polling loop: LDA + BPL (wait until high bit set)
  int lda_count = 0;
  for (const auto& i : insns) {
    if (Mnemonic(i, "LDA")) ++lda_count;
  }
  return lda_count >= 1 && bpl_count >= 1;
}

// Detect dispatch tables: multiple CMP #N / BEQ pattern
// or JMP (table,X) pattern.
bool IsDispatchTable(const std::vector<core::Instruction>& insns) {
  int cmp_count = 0, beq_count = 0;
  for (const auto& i : insns) {
    if (Mnemonic(i, "CMP")) ++cmp_count;
    if (Mnemonic(i, "BEQ")) ++beq_count;
    // JMP (addr,X) — indexed indirect jump table
    if (Mnemonic(i, "JMP") &&
        i.mode == core::AddressingMode::ABSOLUTE_INDEXED_INDIRECT) {
      return true;
    }
  }
  return cmp_count >= 2 && beq_count >= 2;
}

// Format the instruction list as a comment listing.
std::string BuildListing(const std::vector<core::Instruction>& insns) {
  std::ostringstream oss;
  for (const auto& i : insns) {
    oss << "$" << std::hex << std::setw(4) << std::setfill('0')
        << std::uppercase << i.address << "  ";
    for (size_t b = 0; b < i.bytes.size() && b < 3; ++b) {
      oss << std::hex << std::setw(2) << std::setfill('0')
          << std::uppercase << static_cast<int>(i.bytes[b]) << " ";
    }
    for (size_t b = i.bytes.size(); b < 3; ++b) oss << "   ";
    oss << "  " << i.mnemonic;
    if (!i.operand.empty()) oss << " " << i.operand;
    oss << "\n";
  }
  return oss.str();
}

// Classify the best matching pattern for a subroutine.
CodePattern Classify(const std::vector<core::Instruction>& insns) {
  if (HasIsrPrologue(insns) && HasIsrEpilogue(insns)) return CodePattern::ISR_HANDLER;
  if (IsStringOp(insns))      return CodePattern::STRING_OP;
  if (IsGraphicsRoutine(insns)) return CodePattern::GRAPHICS;
  if (IsMathRoutine(insns))   return CodePattern::MATH;
  if (IsMemoryOp(insns))      return CodePattern::MEMORY_OP;
  if (IsDispatchTable(insns)) return CodePattern::DISPATCH_TABLE;
  if (IsIoPolling(insns))     return CodePattern::IO_POLLING;
  return CodePattern::UNKNOWN;
}

}  // namespace

// static
std::vector<PatternCandidate> CodePatternDetector::Detect(
    const core::Binary& /*binary*/,
    const core::AddressMap& address_map,
    const std::vector<core::Instruction>& all_instructions) {
  std::vector<PatternCandidate> candidates;
  if (all_instructions.empty()) return candidates;

  // Split all_instructions into subroutines.  A new subroutine begins at
  // any CODE address that has a label AND is at the start of a basic block
  // (right after a return, jump, or at address 0).  We take a simpler
  // approach: split on labels within CODE regions.

  // Group instructions by subroutine.  Start a new group whenever an
  // address has a non-empty label and the previous group had a return/jump.
  std::vector<std::vector<core::Instruction>> subroutines;
  std::vector<core::Instruction> current;

  for (const auto& inst : all_instructions) {
    if (address_map.GetType(inst.address) != core::AddressType::CODE) {
      // Flush current and skip non-code instructions.
      if (!current.empty()) {
        subroutines.push_back(std::move(current));
        current.clear();
      }
      continue;
    }

    // Start a new subroutine if we see a label after a return/jump.
    bool has_label = false;
    auto lbl = address_map.GetLabel(inst.address);
    if (lbl && !lbl->empty()) has_label = true;

    bool should_split = has_label && !current.empty()
                        && (current.back().is_return || current.back().is_jump);

    if (should_split) {
      subroutines.push_back(std::move(current));
      current.clear();
    }

    current.push_back(inst);
  }
  if (!current.empty()) subroutines.push_back(std::move(current));

  // Classify each subroutine.
  for (auto& sub : subroutines) {
    if (static_cast<int>(sub.size()) < kMinInstructions) continue;

    CodePattern pattern = Classify(sub);
    if (pattern == CodePattern::UNKNOWN) continue;

    PatternCandidate cand;
    cand.start_address = sub.front().address;
    cand.end_address = sub.back().address
                       + static_cast<uint32_t>(sub.back().bytes.size()) - 1;
    cand.pattern = pattern;
    cand.instructions = sub;
    cand.disasm_listing = BuildListing(sub);

    LOG_DEBUG([&] {
      std::ostringstream dbg;
      dbg << "CodePatternDetector: " << PatternName(pattern)
          << " at $" << std::hex << cand.start_address;
      return dbg.str();
    }());
    candidates.push_back(std::move(cand));
  }

  return candidates;
}

// static
std::string CodePatternDetector::PatternName(CodePattern p) {
  switch (p) {
    case CodePattern::STRING_OP:      return "STRING_OP";
    case CodePattern::GRAPHICS:       return "GRAPHICS";
    case CodePattern::MATH:           return "MATH";
    case CodePattern::MEMORY_OP:      return "MEMORY_OP";
    case CodePattern::IO_POLLING:     return "IO_POLLING";
    case CodePattern::DISPATCH_TABLE: return "DISPATCH_TABLE";
    case CodePattern::ISR_HANDLER:    return "ISR_HANDLER";
    default:                          return "UNKNOWN";
  }
}

}  // namespace llm
}  // namespace analysis
}  // namespace sourcerer
