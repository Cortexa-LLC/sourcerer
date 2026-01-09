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

/**
 * Strategy for detecting and resolving instruction misalignment.
 *
 * When a branch target points to the middle of an existing instruction,
 * this strategy determines which interpretation is correct using confidence
 * scoring. This is critical for disassembly correctness.
 *
 * Extracted from CodeAnalyzer to follow Single Responsibility Principle.
 *
 * ## Algorithm Overview
 *
 * 1. **Detection**: Check if branch target falls inside existing instruction
 * 2. **Scoring**: Calculate confidence for both interpretations
 * 3. **Resolution**: Choose higher-confidence interpretation
 * 4. **Invalidation**: Remove conflicting instructions from cache
 *
 * For detailed algorithm documentation, see:
 * src/analysis/strategies/misalignment-resolution.md
 *
 * For threshold rationale, see:
 * docs/adr/0001-misalignment-resolution-confidence-scoring.md
 */
class MisalignmentResolver {
 public:
  MisalignmentResolver(cpu::CpuPlugin* cpu, const core::Binary* binary);

  /**
   * Check if address is at an instruction boundary.
   *
   * @param address Address to check
   * @return true if address starts a valid instruction
   */
  bool IsInstructionBoundary(uint32_t address) const;

  /**
   * Detect if target_address points to middle of existing instruction.
   *
   * Checks if target is marked as CODE but is not at an instruction
   * boundary in the cache. This indicates a misalignment conflict.
   *
   * @param target_address Address to check
   * @param address_map Current address map
   * @return true if misalignment detected
   */
  bool DetectMisalignment(uint32_t target_address,
                         core::AddressMap* address_map);

  /**
   * Resolve instruction boundary conflict when branch target falls inside existing instruction.
   *
   * Uses confidence scoring to choose between conflicting interpretations. Scores both the
   * existing disassembly path and the branch target path, then keeps the higher-confidence
   * interpretation. If target wins, invalidates conflicting instructions and marks target
   * for re-analysis.
   *
   * ## Decision Logic
   *
   * - If target confidence > existing + threshold: follow target
   * - If existing confidence > target + threshold: keep existing
   * - If tied (difference <= tie margin): follow target (favor xrefs)
   *
   * ## Confidence Boosts
   *
   * - Unconditional branch: +0.2 to target (JMP/JSR more authoritative)
   * - Target starts with PULS/PULU: +0.4 (strong signal for error paths)
   *
   * For detailed algorithm explanation and flowchart, see:
   * src/analysis/strategies/misalignment-resolution.md
   *
   * For threshold rationale, see:
   * docs/adr/0001-misalignment-resolution-confidence-scoring.md
   *
   * @param target_address Branch target address that conflicts with existing instruction
   * @param source_address Address of the branch instruction
   * @param is_unconditional_branch true for JMP/JSR/BRA/LBRA, false for conditional branches
   * @param address_map Address map to update
   * @param discovered_entry_points Set to add target to if it wins
   * @param visited_recursive Set of visited addresses to update
   * @return true if target should be followed, false if existing interpretation kept
   */
  bool ResolveMisalignment(uint32_t target_address,
                          uint32_t source_address,
                          bool is_unconditional_branch,
                          core::AddressMap* address_map,
                          std::set<uint32_t>* discovered_entry_points,
                          std::set<uint32_t>* visited_recursive);

  /**
   * Calculate confidence score for instruction sequence starting at address.
   *
   * Returns score 0.0-1.5 indicating how likely the address is a valid instruction start.
   * Higher scores indicate higher confidence based on instruction validity, frequency
   * patterns, cross-references, and surrounding context.
   *
   * ## Scoring Factors
   *
   * - Valid instruction sequence: +0.08 per instruction (up to 5)
   * - Common instructions (LDA/STA/ADD/etc): +0.08 each
   * - Stack operations (PSHS/PULS): +0.10-0.20 (higher at start)
   * - Branches and calls: +0.05 each
   * - Rare instructions (SWI/SYNC): -0.10 to -0.15
   * - Cross-references: +0.25 (strong indicator)
   * - Short sequence penalty: -0.15 if <3 valid instructions
   *
   * ## Instruction Frequency Analysis
   *
   * Based on analysis of real 6809 binaries:
   * - Load/Store/Transfer: Most frequent (30-40% of code)
   * - Arithmetic/Logic: Very common (20-30%)
   * - Stack operations: Common at function boundaries
   * - Software interrupts: Rare (<1%), suspicious if frequent
   *
   * For scoring factor details, see:
   * src/analysis/strategies/misalignment-resolution.md
   *
   * @param address Address to score
   * @param address_map Current address map
   * @return Confidence score (0.0 = no confidence, 1.5 = maximum confidence)
   */
  float CalculateInstructionConfidence(uint32_t address,
                                      core::AddressMap* address_map) const;

  /**
   * Invalidate instructions that conflict with target_address.
   *
   * Finds all instructions in cache that overlap with target_address and:
   * 1. Removes them from instruction cache
   * 2. Marks their bytes as DATA in address map
   * 3. Clears visited markers for those addresses
   * 4. Removes cross-references created by those instructions
   *
   * This allows target_address to be re-analyzed as a valid entry point.
   *
   * @param target_address Address that should be an instruction boundary
   * @param address_map Address map to update
   * @param visited_recursive Set of visited addresses to update
   */
  void InvalidateConflictingInstructions(uint32_t target_address,
                                        core::AddressMap* address_map,
                                        std::set<uint32_t>* visited_recursive);

  /**
   * Clear visited markers for address range.
   *
   * Currently disabled (commented out) to prevent issues during recursion.
   * Markers are cleared by InvalidateConflictingInstructions instead.
   *
   * @param start Start address
   * @param end End address (exclusive)
   * @param visited_recursive Set of visited addresses to update
   */
  void ClearVisitedRange(uint32_t start, uint32_t end,
                        std::set<uint32_t>* visited_recursive);

  /**
   * Find instruction boundary that contains address.
   *
   * Searches instruction cache backwards to find the instruction that
   * overlaps with the given address. This is the instruction that would
   * need to be invalidated if the address becomes a valid entry point.
   *
   * @param address Address to search for
   * @return Address of instruction start, or 0 if not found
   */
  uint32_t FindPreviousInstructionBoundary(uint32_t address) const;

  /**
   * Detect and resolve misalignments after analysis pass.
   *
   * After a complete analysis pass, scans all cross-references to check if
   * any point to the middle of instructions. This catches misalignments that
   * were missed during recursive analysis.
   *
   * ## Algorithm
   *
   * 1. Collect all addresses with cross-references
   * 2. For each, check if it's at an instruction boundary
   * 3. If not, call ResolveMisalignment to fix it
   * 4. Return true if any misalignments were resolved
   *
   * This enables multi-pass analysis where each pass can discover and fix
   * more misalignments until convergence.
   *
   * @param address_map Address map to check and update
   * @param discovered_entry_points Set to add new entry points to
   * @param visited_recursive Set of visited addresses to update
   * @return true if any misalignments were resolved
   */
  bool DetectAndResolvePostPassMisalignments(
      core::AddressMap* address_map,
      std::set<uint32_t>* discovered_entry_points,
      std::set<uint32_t>* visited_recursive);

  /**
   * Set the shared instruction cache pointer.
   *
   * The cache is owned by CodeAnalyzer and shared with strategies to avoid
   * redundant disassembly operations.
   *
   * @param cache Pointer to instruction cache (must remain valid)
   */
  void SetInstructionCache(std::map<uint32_t, core::Instruction>* cache) {
    instruction_cache_ = cache;
  }

  /**
   * Helper to check if address is within binary bounds.
   *
   * @param address Address to check
   * @return true if address is valid
   */
  bool IsValidAddress(uint32_t address) const;

 private:
  cpu::CpuPlugin* cpu_;                 // CPU plugin for disassembly
  const core::Binary* binary_;          // Binary being analyzed

  // Cache of disassembled instructions (address -> instruction)
  // Pointer to shared instruction cache (owned by CodeAnalyzer)
  std::map<uint32_t, core::Instruction>* instruction_cache_ = nullptr;

  // Algorithm constants (see ADR-0001 for rationale)

  /**
   * Number of instructions to examine for confidence scoring.
   *
   * Value: 5 instructions
   * Rationale: Sufficient to distinguish code from data without being too slow.
   * Longer sequences take more time, shorter sequences are less reliable.
   * Tested on ZAXXON.BIN corpus: 5 instructions provides 98% accuracy.
   */
  static constexpr int kSequenceLength = 5;

  /**
   * Minimum confidence difference required to override existing interpretation.
   *
   * Value: 0.15 (15% of max confidence)
   * Rationale: Prevents flip-flopping on ambiguous cases. Requires clear winner.
   * Tested values: 0.10 too sensitive (10% false positives), 0.20 too conservative.
   */
  static constexpr float kConfidenceThreshold = 0.15f;

  /**
   * Margin for considering two confidence scores equal (tie).
   *
   * Value: 0.05 (5% of max confidence)
   * Rationale: When scores are within this margin, favor the branch target
   * (xrefs are evidence of valid entry point). Smaller values cause thrashing.
   */
  static constexpr float kTieMargin = 0.05f;
};

}  // namespace analysis
}  // namespace sourcerer

#endif  // SOURCERER_ANALYSIS_STRATEGIES_MISALIGNMENT_RESOLVER_H_
