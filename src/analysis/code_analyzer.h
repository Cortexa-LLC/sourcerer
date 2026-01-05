// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_ANALYSIS_CODE_ANALYZER_H_
#define SOURCERER_ANALYSIS_CODE_ANALYZER_H_

#include <cstdint>
#include <memory>
#include <queue>
#include <set>
#include <vector>

#include "core/address_map.h"
#include "core/binary.h"
#include "core/instruction.h"
#include "cpu/cpu_plugin.h"

namespace sourcerer {
namespace analysis {

// Code flow analyzer - follows branches and calls to identify code vs data
class CodeAnalyzer {
 public:
  CodeAnalyzer(cpu::CpuPlugin* cpu, const core::Binary* binary);

  // Analyze code flow starting from entry points
  // Returns a map of addresses that have been analyzed
  void Analyze(core::AddressMap* address_map);

  // Add an entry point to start analysis from
  void AddEntryPoint(uint32_t address);

  // Find the first valid instruction starting from address
  // Useful for skipping ROM headers or other non-code prefixes
  uint32_t FindFirstValidInstruction(uint32_t start_address) const;

  // Set maximum number of instructions to analyze (safety limit)
  void SetMaxInstructions(size_t max) { max_instructions_ = max; }

  // Get statistics
  size_t GetInstructionCount() const { return instruction_count_; }
  size_t GetCodeBytes() const { return code_bytes_; }
  size_t GetDataBytes() const { return data_bytes_; }

  // NEW: Recursive analysis API
  void RecursiveAnalyze(core::AddressMap* address_map);

 private:
  cpu::CpuPlugin* cpu_;
  const core::Binary* binary_;
  std::set<uint32_t> entry_points_;
  size_t max_instructions_ = 100000;  // Safety limit

  // Statistics
  size_t instruction_count_ = 0;
  size_t code_bytes_ = 0;
  size_t data_bytes_ = 0;

  // Track subroutines that use inline data (read params from after JSR)
  std::set<uint32_t> inline_data_routines_;

  // Known platform-specific inline data routines (like ProDOS MLI)
  std::map<uint32_t, size_t> known_inline_data_routines_;  // address -> bytes_after_call

  // Queue-based analysis
  void AnalyzeFromQueue(core::AddressMap* address_map);

  // Process a single address
  void ProcessAddress(uint32_t address,
                     core::AddressMap* address_map,
                     std::queue<uint32_t>* queue,
                     std::set<uint32_t>* visited);

  // Check if address is valid and within binary bounds
  bool IsValidAddress(uint32_t address) const;

  // Check if instruction should stop current path
  bool ShouldStopPath(const core::Instruction& inst) const;

  // Check if a subroutine uses inline data pattern
  // (pulls return address, reads data, adjusts it, pushes back)
  bool IsInlineDataRoutine(uint32_t address, core::AddressMap* address_map);

  // Scan inline data after JSR and return address after data
  // Returns 0 if no valid terminator found
  uint32_t ScanInlineData(uint32_t start_address, core::AddressMap* address_map);

  // Second pass: Reclassify CODE after computed jumps
  void ReclassifyAfterComputedJumps(core::AddressMap* address_map);

  // Third pass: Detect and reclassify mixed CODE/DATA regions (phantom instructions)
  void ReclassifyMixedCodeDataRegions(core::AddressMap* address_map);

  // Fourth pass: Reclassify CODE regions that look like data
  void ReclassifyDataRegions(core::AddressMap* address_map);

  // Check if a CODE region looks more like data than code
  bool LooksLikeData(uint32_t start_address, uint32_t end_address) const;

  // Calculate percentage of printable ASCII bytes in a region
  float CalculatePrintablePercentage(uint32_t start, uint32_t end) const;

  // NEW: Conservative reclassification constants
  static constexpr size_t MIN_DATA_REGION_SIZE = 16;   // Reduced to catch graphics
  static constexpr int MIN_HEURISTIC_MATCHES = 2;      // Require 2+ heuristics
  static constexpr float PRINTABLE_THRESHOLD_HIGH = 0.90f;  // Raised from 0.80

  // NEW: Helper methods for individual heuristics
  int CountDataHeuristics(uint32_t start, uint32_t end) const;
  bool HasLongPrintableSequence(uint32_t start, uint32_t end) const;
  bool HasNullTerminatedStrings(uint32_t start, uint32_t end) const;
  bool HasRepeatedBytes(uint32_t start, uint32_t end) const;
  bool HasAddressLikePairs(uint32_t start, uint32_t end) const;
  bool HasRepeatedInstructions(uint32_t start, uint32_t end) const;
  bool HasHighIllegalDensity(uint32_t start, uint32_t end) const;
  int CountXrefsInRange(core::AddressMap* address_map,
                       uint32_t start, uint32_t end) const;

  // Graphics data detection heuristics
  bool HasBitmapEntropy(uint32_t start, uint32_t end) const;
  bool HasByteAlignment(uint32_t start, uint32_t end) const;
  bool IsInGraphicsRegion(uint32_t start, uint32_t end) const;
  bool HasSpritePatterns(uint32_t start, uint32_t end) const;
  float CalculateEntropy(const uint8_t* data, size_t length) const;

  // NEW: Recursive traversal methods
  void AnalyzeRecursively(uint32_t address, core::AddressMap* address_map,
                         int depth = 0);
  int RunAnalysisPass(core::AddressMap* address_map);

  // Recursion depth limit
  static constexpr int MAX_RECURSION_DEPTH = 1000;

  // Track visited addresses to prevent infinite recursion
  std::set<uint32_t> visited_recursive_;

  // Recursive analysis statistics
  int code_bytes_discovered_ = 0;
  int passes_completed_ = 0;

  // NEW: Entry point discovery (Phase 3 - SOLID architecture)
  void DiscoverEntryPoints(core::AddressMap* address_map);
  void ScanInterruptVectors();  // CPU-agnostic vector scanning
  void ScanForSubroutinePatterns(core::AddressMap* address_map);
  bool LooksLikeSubroutineStart(uint32_t address) const;  // Delegates to CPU plugin
  bool IsLikelyCode(uint32_t address, size_t scan_length = 16) const;  // Delegates to CPU plugin

  // CoCo-specific entry point detection
  void ScanCoCoCartridgeEntryPoints();
  void ScanCoCoStandardEntryPoints();
  bool IsCoCoCartridgeSpace(uint32_t address) const;
  bool HasCoCoPreamble(uint32_t address) const;

  std::set<uint32_t> discovered_entry_points_;
  std::set<uint32_t> lea_targets_;  // LEA/LEAX/LEAY target addresses (potential data)

  // NEW: Jump table detection (Phase 4)
  struct JumpTableCandidate {
    uint32_t start_address;        // First entry in table
    uint32_t end_address;          // Last entry in table
    std::vector<uint32_t> targets; // Extracted target addresses
    float confidence;              // 0.0 to 1.0 confidence score

    size_t GetEntryCount() const { return targets.size(); }
    size_t GetTableSize() const { return end_address - start_address + 1; }
  };

  void ScanForJumpTables(core::AddressMap* address_map);
  std::vector<JumpTableCandidate> FindJumpTableCandidates(
      core::AddressMap* address_map) const;
  bool ValidateJumpTable(const JumpTableCandidate& candidate,
                        core::AddressMap* address_map) const;
  void ProcessJumpTable(const JumpTableCandidate& table,
                        core::AddressMap* address_map);
  float CalculateTableConfidence(const JumpTableCandidate& candidate) const;
  bool IsLikelyCodePointer(uint16_t address) const;

  // Jump table configuration constants
  static constexpr size_t MIN_JUMP_TABLE_ENTRIES = 3;
  static constexpr size_t MAX_JUMP_TABLE_ENTRIES = 256;
  static constexpr float MIN_CONFIDENCE = 0.6f;

  // NEW: Misalignment detection and resolution
  std::map<uint32_t, core::Instruction> instruction_cache_;  // Cache disassembled instructions

  // Check if address is at an instruction boundary
  bool IsInstructionBoundary(uint32_t address) const;

  // Detect misalignment: branch target is in middle of existing instruction
  bool DetectMisalignment(uint32_t target_address, core::AddressMap* address_map);

  // Resolve misalignment by evaluating which path is more likely correct
  // Returns true if misalignment was resolved (target should be followed)
  bool ResolveMisalignment(uint32_t target_address, uint32_t source_address,
                           bool is_unconditional_branch,
                           core::AddressMap* address_map);

  // Calculate confidence score for an instruction starting at address
  // Higher score = more likely to be correct code
  float CalculateInstructionConfidence(uint32_t address,
                                       core::AddressMap* address_map) const;

  // Invalidate instruction(s) that conflict with target address
  void InvalidateConflictingInstructions(uint32_t target_address,
                                         core::AddressMap* address_map);

  // Clear visited markers for a range of addresses (allow re-analysis)
  void ClearVisitedRange(uint32_t start, uint32_t end);

  // Find instruction boundary at or before address
  uint32_t FindPreviousInstructionBoundary(uint32_t address) const;

  // Post-pass: detect and resolve misalignments after all paths explored
  bool DetectAndResolvePostPassMisalignments(core::AddressMap* address_map);

  // NEW: Dynamic analysis using execution simulation
  void DynamicAnalysis(core::AddressMap* address_map);
};

}  // namespace analysis
}  // namespace sourcerer

#endif  // SOURCERER_ANALYSIS_CODE_ANALYZER_H_
