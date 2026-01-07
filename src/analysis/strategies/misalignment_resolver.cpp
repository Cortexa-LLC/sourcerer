// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "analysis/strategies/misalignment_resolver.h"

#include <algorithm>
#include <cmath>
#include <sstream>

#include "utils/logger.h"

namespace sourcerer {
namespace analysis {

MisalignmentResolver::MisalignmentResolver(cpu::CpuPlugin* cpu,
                                           const core::Binary* binary)
    : cpu_(cpu), binary_(binary) {}

bool MisalignmentResolver::IsValidAddress(uint32_t address) const {
  uint32_t start = binary_->load_address();
  uint32_t end = start + binary_->size();
  return address >= start && address < end;
}

// Cache methods removed - now uses shared cache pointer

bool MisalignmentResolver::IsInstructionBoundary(uint32_t address) const {
  if (!instruction_cache_) return false;
  return instruction_cache_->find(address) != instruction_cache_->end();
}

bool MisalignmentResolver::DetectMisalignment(uint32_t target_address,
                                              core::AddressMap* address_map) {
  // Check if target is CODE but NOT at an instruction boundary
  if (!address_map->IsCode(target_address)) {
    return false;  // Not CODE, no misalignment
  }

  if (IsInstructionBoundary(target_address)) {
    return false;  // Valid boundary, no misalignment
  }

  // Target is CODE but not at instruction start = misalignment!
  return true;
}

uint32_t MisalignmentResolver::FindPreviousInstructionBoundary(
    uint32_t address) const {
  // Search backwards in cache for closest instruction boundary
  uint32_t closest = 0;

  for (const auto& pair : *instruction_cache_) {
    uint32_t inst_addr = pair.first;
    const core::Instruction& inst = pair.second;

    // Check if this instruction overlaps with target address
    uint32_t inst_end = inst_addr + inst.bytes.size();
    if (inst_addr <= address && address < inst_end) {
      return inst_addr;  // Found the instruction containing this address
    }
  }

  return closest;
}

float MisalignmentResolver::CalculateInstructionConfidence(
    uint32_t address, core::AddressMap* address_map) const {
  float confidence = 0.5f;  // Baseline

  // Try to disassemble a sequence of instructions from this address
  uint32_t current = address;
  int valid_sequence = 0;

  // Track instruction frequency patterns
  int rare_instruction_count = 0;
  int common_instruction_count = 0;

  for (int i = 0; i < kSequenceLength; ++i) {
    if (!IsValidAddress(current)) break;

    const uint8_t* data = binary_->GetPointer(current);
    size_t remaining = binary_->load_address() + binary_->size() - current;
    if (!data || remaining == 0) break;

    core::Instruction inst;
    try {
      inst = cpu_->Disassemble(data, remaining, current);
    } catch (const std::exception& e) {
      LOG_DEBUG("Disassembly failed at $" + std::to_string(current) +
                " during confidence calculation: " + e.what());
      break;
    }

    if (inst.bytes.empty() || inst.is_illegal) break;

    valid_sequence++;

    // ========== INSTRUCTION FREQUENCY ANALYSIS ==========

    // VERY COMMON: Load/Store/Transfer (highest frequency in typical code)
    if (inst.mnemonic == "LDA" || inst.mnemonic == "LDB" || inst.mnemonic == "LDD" ||
        inst.mnemonic == "LDX" || inst.mnemonic == "LDY" || inst.mnemonic == "LDU" ||
        inst.mnemonic == "STA" || inst.mnemonic == "STB" || inst.mnemonic == "STD" ||
        inst.mnemonic == "STX" || inst.mnemonic == "STY" || inst.mnemonic == "STU" ||
        inst.mnemonic == "TFR" || inst.mnemonic == "EXG") {
      confidence += 0.08f;
      common_instruction_count++;
    }
    // VERY COMMON: Arithmetic/Logic
    else if (inst.mnemonic == "ADDA" || inst.mnemonic == "ADDB" || inst.mnemonic == "ADDD" ||
             inst.mnemonic == "SUBA" || inst.mnemonic == "SUBB" || inst.mnemonic == "SUBD" ||
             inst.mnemonic == "CMPA" || inst.mnemonic == "CMPB" || inst.mnemonic == "CMPD" ||
             inst.mnemonic == "CMPX" || inst.mnemonic == "CMPY" ||
             inst.mnemonic == "ANDA" || inst.mnemonic == "ANDB" || inst.mnemonic == "ANDCC" ||
             inst.mnemonic == "ORA" || inst.mnemonic == "ORB" || inst.mnemonic == "ORCC" ||
             inst.mnemonic == "EORA" || inst.mnemonic == "EORB") {
      confidence += 0.08f;
      common_instruction_count++;
    }
    // VERY COMMON: Stack operations (especially at subroutine entry/exit)
    else if (inst.mnemonic == "PSHS" || inst.mnemonic == "PULS" ||
             inst.mnemonic == "PSHU" || inst.mnemonic == "PULU") {
      if (i == 0) {
        confidence += 0.20f;  // VERY likely at branch target
      } else {
        confidence += 0.10f;
      }
      common_instruction_count++;
    }
    // VERY COMMON: Branches and subroutine calls
    else if (inst.mnemonic == "BEQ" || inst.mnemonic == "BNE" || inst.mnemonic == "BCC" ||
             inst.mnemonic == "BCS" || inst.mnemonic == "BVC" || inst.mnemonic == "BVS" ||
             inst.mnemonic == "BPL" || inst.mnemonic == "BMI" || inst.mnemonic == "BGE" ||
             inst.mnemonic == "BLT" || inst.mnemonic == "BGT" || inst.mnemonic == "BLE" ||
             inst.mnemonic == "BHI" || inst.mnemonic == "BLS" || inst.mnemonic == "BRA" ||
             inst.mnemonic == "BSR" || inst.mnemonic == "JSR" || inst.mnemonic == "LBRA" ||
             inst.mnemonic == "LBSR") {
      confidence += 0.05f;
      common_instruction_count++;
    }
    // COMMON: Return, increment/decrement, shift/rotate
    else if (inst.mnemonic == "RTS" || inst.mnemonic == "RTI" ||
             inst.mnemonic == "INCA" || inst.mnemonic == "INCB" || inst.mnemonic == "INC" ||
             inst.mnemonic == "DECA" || inst.mnemonic == "DECB" || inst.mnemonic == "DEC" ||
             inst.mnemonic == "LSLA" || inst.mnemonic == "LSLB" || inst.mnemonic == "LSL" ||
             inst.mnemonic == "LSRA" || inst.mnemonic == "LSRB" || inst.mnemonic == "LSR" ||
             inst.mnemonic == "ASRA" || inst.mnemonic == "ASRB" || inst.mnemonic == "ASR" ||
             inst.mnemonic == "ROLA" || inst.mnemonic == "ROLB" || inst.mnemonic == "ROL" ||
             inst.mnemonic == "RORA" || inst.mnemonic == "RORB" || inst.mnemonic == "ROR") {
      confidence += 0.05f;
      common_instruction_count++;
    }
    // COMMON: Test, clear, negate
    else if (inst.mnemonic == "TSTA" || inst.mnemonic == "TSTB" || inst.mnemonic == "TST" ||
             inst.mnemonic == "CLRA" || inst.mnemonic == "CLRB" || inst.mnemonic == "CLR" ||
             inst.mnemonic == "NEGA" || inst.mnemonic == "NEGB" || inst.mnemonic == "NEG" ||
             inst.mnemonic == "COMA" || inst.mnemonic == "COMB" || inst.mnemonic == "COM") {
      confidence += 0.05f;
      common_instruction_count++;
    }
    // COMMON: LEA operations (address calculation)
    else if (inst.mnemonic == "LEAX" || inst.mnemonic == "LEAY" ||
             inst.mnemonic == "LEAS" || inst.mnemonic == "LEAU") {
      confidence += 0.05f;
      common_instruction_count++;
    }
    // RARE: Software interrupts (should be infrequent in typical code)
    else if (inst.mnemonic == "SWI" || inst.mnemonic == "SWI2" || inst.mnemonic == "SWI3") {
      confidence -= 0.15f;
      rare_instruction_count++;

      // VERY suspicious if SWI appears early in sequence
      if (i < 3) {
        confidence -= 0.15f;  // Extra penalty
      }
    }
    // RARE: Synchronization and wait instructions
    else if (inst.mnemonic == "SYNC" || inst.mnemonic == "CWAI") {
      confidence -= 0.10f;
      rare_instruction_count++;
    }
    // RARE: Multiply/divide (less common in typical 6809 code)
    else if (inst.mnemonic == "MUL" || inst.mnemonic == "DIV") {
      // Don't penalize, but don't boost either (neutral)
    }
    // MODERATE: Other instructions (SEX, DAA, ABX, etc.)
    else {
      confidence += 0.02f;  // Small boost for valid instruction
    }

    // ========== PATTERN ANALYSIS ==========

    // Suspicious: Multiple rare instructions in a row
    if (rare_instruction_count >= 2) {
      confidence -= 0.20f;
    }

    // Good: Multiple common instructions in a row
    if (common_instruction_count >= 3) {
      confidence += 0.15f;
    }

    current += inst.bytes.size();
  }

  // Confidence boost based on sequence length (longer = better)
  confidence += (valid_sequence * 0.08f);

  // Penalty for short sequences (might be data that happens to decode)
  if (valid_sequence < 3) {
    confidence -= 0.15f;
  }

  // Check if this address has xrefs (branches pointing to it)
  const auto& xrefs = address_map->GetXrefs(address);
  if (!xrefs.empty()) {
    confidence += 0.25f;  // Strong indicator of valid code target
  }

  // Cap confidence between 0.0 and 1.5 (allow exceeding 1.0 for very strong signals)
  if (confidence < 0.0f) confidence = 0.0f;
  if (confidence > 1.5f) confidence = 1.5f;

  return confidence;
}

bool MisalignmentResolver::ResolveMisalignment(
    uint32_t target_address, uint32_t source_address,
    bool is_unconditional_branch, core::AddressMap* address_map,
    std::set<uint32_t>* discovered_entry_points,
    std::set<uint32_t>* visited_recursive) {
  // Find the existing instruction that contains target_address
  uint32_t existing_inst_start = FindPreviousInstructionBoundary(target_address);

  if (existing_inst_start == 0) {
    // Couldn't find existing instruction, allow target
    std::stringstream ss_dbg;
    ss_dbg << std::hex << std::uppercase << "$" << target_address;
    LOG_DEBUG("No existing instruction found containing " + ss_dbg.str() +
              ", allowing branch target");

    // Mark target and surrounding bytes as UNKNOWN to force re-analysis
    // This handles cases where cache was cleared but address_map still has stale CODE markers
    // Use a larger range (32 bytes) to ensure proper re-analysis
    for (uint32_t addr = target_address; addr < target_address + 32 && IsValidAddress(addr); ++addr) {
      if (address_map->GetType(addr) == core::AddressType::CODE) {
        address_map->SetType(addr, core::AddressType::UNKNOWN);
        // visited_recursive->erase(addr);  // Dont erase during recursion
      }
    }

    // Add to discovered entry points so next pass will analyze from here
    discovered_entry_points->insert(target_address);
    return true;
  }

  const core::Instruction& existing_inst = (*instruction_cache_)[existing_inst_start];

  std::stringstream ss;
  ss << std::hex << std::uppercase;

  LOG_DEBUG("Misalignment detected:");
  ss.str(""); ss << "$" << source_address;
  std::string src_hex = ss.str();
  ss.str(""); ss << "$" << target_address;
  std::string tgt_hex = ss.str();
  LOG_DEBUG("  Branch from " + src_hex + " to " + tgt_hex);

  ss.str(""); ss << "$" << existing_inst_start;
  LOG_DEBUG("  Conflicts with existing instruction at " + ss.str() + ": " +
            existing_inst.mnemonic + " " + existing_inst.operand);

  // Calculate confidence for both interpretations
  float target_confidence = CalculateInstructionConfidence(target_address, address_map);
  float existing_confidence = CalculateInstructionConfidence(existing_inst_start, address_map);

  // Boost target confidence if it's an unconditional branch/jump
  if (is_unconditional_branch) {
    target_confidence += 0.2f;
    LOG_DEBUG("  Unconditional branch - boosting target confidence");
  }

  // CRITICAL: Check if target starts with PULS/POPS that matches recent PSHS/PSHU
  // This is a VERY strong signal for error handling paths
  const uint8_t* target_data = binary_->GetPointer(target_address);
  if (target_data) {
    uint8_t target_opcode = target_data[0];
    // PULS ($35) or PULU ($37)
    if (target_opcode == 0x35 || target_opcode == 0x37) {
      // Huge boost - stack cleanup after conditional error path is extremely common
      target_confidence += 0.4f;
      LOG_INFO("  Target starts with PULS/PULU (stack cleanup) - strong boost!");
    }
  }

  // Check fallthrough from existing instruction
  uint32_t fallthrough_addr = existing_inst_start + existing_inst.bytes.size();
  float fallthrough_confidence = 0.0f;
  if (IsValidAddress(fallthrough_addr)) {
    fallthrough_confidence = CalculateInstructionConfidence(fallthrough_addr, address_map);
  }

  LOG_INFO("  Confidence scores:");
  ss.str(""); ss << "$" << existing_inst_start;
  LOG_INFO("    Existing instruction at " + ss.str() +
            ": " + std::to_string(existing_confidence));
  ss.str(""); ss << "$" << fallthrough_addr;
  LOG_INFO("    Fallthrough at " + ss.str() +
            ": " + std::to_string(fallthrough_confidence));
  ss.str(""); ss << "$" << target_address;
  LOG_INFO("    Branch target at " + ss.str() +
            ": " + std::to_string(target_confidence));

  // Decision logic:
  // If target confidence significantly higher, invalidate existing and use target
  // If existing confidence higher, keep existing and ignore branch
  // If tied, prefer branch target (tiebreaker: xref existence is evidence)
  bool is_tied = (std::abs(target_confidence - existing_confidence) <= kTieMargin);

  if (target_confidence > existing_confidence + kConfidenceThreshold || is_tied) {
    LOG_INFO("Resolving misalignment: branch target wins (confidence " +
             std::to_string(target_confidence) + " vs " +
             std::to_string(existing_confidence) + ")");
    ss.str(""); ss << "$" << existing_inst_start;
    LOG_INFO("  Invalidating instruction at " + ss.str());

    InvalidateConflictingInstructions(target_address, address_map, visited_recursive);

    // CRITICAL: Also invalidate the fallthrough path from the conflicting instruction
    // because it was based on the wrong interpretation
    uint32_t fallthrough_start = existing_inst_start + existing_inst.bytes.size();
    if (fallthrough_start < target_address) {
      // Mark everything from fallthrough to target as UNKNOWN for re-analysis
      for (uint32_t addr = fallthrough_start; addr < target_address; ++addr) {
        address_map->SetType(addr, core::AddressType::UNKNOWN);
        // visited_recursive->erase(addr);  // Dont erase during recursion  // Allow re-analysis
      }
    }

    // Add to discovered entry points so next pass will analyze from here
    discovered_entry_points->insert(target_address);

    return true;  // Follow the branch target
  } else {
    LOG_DEBUG("Keeping existing instruction (confidence " +
              std::to_string(existing_confidence) + " vs " +
              std::to_string(target_confidence) + ")");
    return false;  // Keep existing, don't follow branch
  }
}

void MisalignmentResolver::ClearVisitedRange(uint32_t start, uint32_t end,
                                             std::set<uint32_t>* /* visited_recursive */) {
  // Remove visited markers for addresses in range
  for (uint32_t addr = start; addr < end; ++addr) {
    // visited_recursive->erase(addr);  // Dont erase during recursion
  }
}

void MisalignmentResolver::InvalidateConflictingInstructions(
    uint32_t target_address, core::AddressMap* address_map,
    std::set<uint32_t>* visited_recursive) {
  if (!instruction_cache_) return;

  // Find all instructions that overlap with target_address
  std::vector<uint32_t> to_invalidate;

  for (const auto& pair : *instruction_cache_) {
    uint32_t inst_addr = pair.first;
    const core::Instruction& inst = pair.second;
    uint32_t inst_end = inst_addr + inst.bytes.size();

    // Check if this instruction overlaps with target
    if (inst_addr < target_address && target_address < inst_end) {
      to_invalidate.push_back(inst_addr);
    }
  }

  // Remove from cache, mark bytes as UNKNOWN, clear visited markers AND xrefs
  for (uint32_t addr : to_invalidate) {
    const core::Instruction& inst = (*instruction_cache_)[addr];

    std::stringstream ss_inv;
    ss_inv << std::hex << std::uppercase << "$" << addr;
    LOG_DEBUG("Invalidating instruction at " + ss_inv.str() +
              ": " + inst.mnemonic + " " + inst.operand);

    // Mark bytes as DATA (not UNKNOWN) to prevent re-analysis as CODE
    // These bytes were part of an invalid instruction that conflicted with a branch target
    for (size_t i = 0; i < inst.bytes.size(); ++i) {
      uint32_t byte_addr = addr + i;
      address_map->SetType(byte_addr, core::AddressType::DATA);

      // CRITICAL: Clear visited marker so target address can be re-analyzed
      visited_recursive->erase(byte_addr);
    }

    // CRITICAL: Remove any xrefs created by this instruction
    // If the instruction is invalid, its branch targets are also invalid
    address_map->RemoveXrefsFrom(addr);

    instruction_cache_->erase(addr);
  }

  // Clear visited marker for target address itself
  visited_recursive->erase(target_address);
}

bool MisalignmentResolver::DetectAndResolvePostPassMisalignments(
    core::AddressMap* address_map,
    std::set<uint32_t>* discovered_entry_points,
    std::set<uint32_t>* visited_recursive) {
  // After a complete pass, check all xrefs to see if any point to the middle of instructions
  bool resolved_any = false;

  // Collect all xref targets
  std::set<uint32_t> xref_targets;
  uint32_t start = binary_->load_address();
  uint32_t end = start + binary_->size();

  for (uint32_t addr = start; addr < end; ++addr) {
    const auto& xrefs = address_map->GetXrefs(addr);
    if (!xrefs.empty()) {
      xref_targets.insert(addr);
    }
  }

  // Check each xref target to see if it's in the middle of an instruction
  for (uint32_t target : xref_targets) {
    if (!address_map->IsCode(target)) {
      continue;  // Not in CODE region, skip
    }

    // Check if this is an instruction boundary
    if (IsInstructionBoundary(target)) {
      continue;  // Valid boundary, no problem
    }

    // This xref points into the middle of an instruction - misalignment!
    const auto& xrefs = address_map->GetXrefs(target);
    if (xrefs.empty()) continue;  // Shouldn't happen, but check anyway

    // Get the source of the xref (first one)
    uint32_t source = *xrefs.begin();

    // Check if source is an unconditional branch/jump
    const uint8_t* source_data = binary_->GetPointer(source);
    if (!source_data) continue;

    size_t source_remaining = end - source;
    core::Instruction source_inst;
    try {
      source_inst = cpu_->Disassemble(source_data, source_remaining, source);
    } catch (const std::exception& e) {
      LOG_DEBUG("Disassembly failed at $" + std::to_string(source) +
                " during post-pass detection: " + e.what());
      continue;
    }

    bool is_unconditional = (source_inst.mnemonic == "BRA" ||
                             source_inst.mnemonic == "LBRA" ||
                             source_inst.mnemonic == "JMP" ||
                             source_inst.mnemonic == "JSR" ||
                             source_inst.mnemonic == "LBSR");

    std::stringstream ss_post;
    ss_post << std::hex << std::uppercase;
    ss_post << "$" << target;
    std::string target_hex = ss_post.str();
    ss_post.str(""); ss_post << "$" << source;
    std::string source_hex = ss_post.str();
    LOG_INFO("Post-pass misalignment detected at " + target_hex +
             " (xref from " + source_hex + ")");

    // Try to resolve
    if (ResolveMisalignment(target, source, is_unconditional, address_map,
                           discovered_entry_points, visited_recursive)) {
      LOG_INFO("  Resolved - will re-analyze");
      resolved_any = true;
    }
  }

  return resolved_any;
}

}  // namespace analysis
}  // namespace sourcerer
