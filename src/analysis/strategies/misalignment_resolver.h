// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_ANALYSIS_STRATEGIES_MISALIGNMENT_RESOLVER_H_
#define SOURCERER_ANALYSIS_STRATEGIES_MISALIGNMENT_RESOLVER_H_

#include <cstdint>
#include <map>
#include <set>

#include "core/address_map.h"
#include "core/binary.h"
#include "core/instruction.h"
#include "cpu/cpu_plugin.h"

namespace sourcerer {
namespace analysis {

// Strategy for detecting and resolving instruction misalignment
// When a branch target points to the middle of an existing instruction,
// this strategy determines which interpretation is correct
// Extracted from CodeAnalyzer to follow Single Responsibility Principle
// CRITICAL: This affects correctness of disassembly
class MisalignmentResolver {
 public:
  MisalignmentResolver(cpu::CpuPlugin* cpu, const core::Binary* binary);

  // Check if address is at an instruction boundary
  bool IsInstructionBoundary(uint32_t address) const;

  // Detect if target_address points to middle of instruction
  bool DetectMisalignment(uint32_t target_address,
                         core::AddressMap* address_map);

  // Resolve misalignment by choosing correct interpretation
  // Returns true if branch should be followed, false if existing kept
  bool ResolveMisalignment(uint32_t target_address,
                          uint32_t source_address,
                          bool is_unconditional_branch,
                          core::AddressMap* address_map,
                          std::set<uint32_t>* discovered_entry_points,
                          std::set<uint32_t>* visited_recursive);

  // Calculate confidence score for instruction sequence starting at address
  float CalculateInstructionConfidence(uint32_t address,
                                      core::AddressMap* address_map) const;

  // Invalidate instructions that conflict with target_address
  void InvalidateConflictingInstructions(uint32_t target_address,
                                        core::AddressMap* address_map,
                                        std::set<uint32_t>* visited_recursive);

  // Clear visited markers for address range
  void ClearVisitedRange(uint32_t start, uint32_t end,
                        std::set<uint32_t>* visited_recursive);

  // Find instruction boundary that contains address
  uint32_t FindPreviousInstructionBoundary(uint32_t address) const;

  // Detect and resolve misalignments after analysis pass
  bool DetectAndResolvePostPassMisalignments(
      core::AddressMap* address_map,
      std::set<uint32_t>* discovered_entry_points,
      std::set<uint32_t>* visited_recursive);

  // Cache management
  // Set the shared instruction cache pointer
  void SetInstructionCache(std::map<uint32_t, core::Instruction>* cache) {
    instruction_cache_ = cache;
  }

  // Helper to check if address is valid
  bool IsValidAddress(uint32_t address) const;
 private:
  cpu::CpuPlugin* cpu_;
  const core::Binary* binary_;

  // Cache of disassembled instructions (address -> instruction)
  // Pointer to shared instruction cache (owned by CodeAnalyzer)
  std::map<uint32_t, core::Instruction>* instruction_cache_ = nullptr;

  // Constants
  static constexpr int kSequenceLength = 5;
  static constexpr float kConfidenceThreshold = 0.15f;
  static constexpr float kTieMargin = 0.05f;
};

}  // namespace analysis
}  // namespace sourcerer

#endif  // SOURCERER_ANALYSIS_STRATEGIES_MISALIGNMENT_RESOLVER_H_
