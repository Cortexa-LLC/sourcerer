// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_ANALYSIS_STRATEGIES_JUMP_TABLE_DETECTOR_H_
#define SOURCERER_ANALYSIS_STRATEGIES_JUMP_TABLE_DETECTOR_H_

#include <cstdint>
#include <set>
#include <vector>

#include "core/address_map.h"
#include "core/binary.h"
#include "cpu/cpu_plugin.h"

namespace sourcerer {
namespace analysis {

// Strategy for detecting jump tables (dispatch tables) in binary code
// Extracted from CodeAnalyzer to follow Single Responsibility Principle
class JumpTableDetector {
 public:
  // Jump table candidate structure
  struct JumpTableCandidate {
    uint32_t start_address;        // First entry in table
    uint32_t end_address;          // Last entry in table
    std::vector<uint32_t> targets; // Extracted target addresses
    float confidence;              // 0.0 to 1.0 confidence score

    size_t GetEntryCount() const { return targets.size(); }
    size_t GetTableSize() const { return end_address - start_address + 1; }
  };

  JumpTableDetector(cpu::CpuPlugin* cpu, const core::Binary* binary);

  // Main interface - scan for and process jump tables
  void ScanForJumpTables(core::AddressMap* address_map,
                         std::set<uint32_t>* discovered_entry_points);

  // Individual jump table operations
  std::vector<JumpTableCandidate> FindJumpTableCandidates(
      core::AddressMap* address_map) const;
  float CalculateTableConfidence(const JumpTableCandidate& candidate) const;
  bool ValidateJumpTable(const JumpTableCandidate& candidate,
                        core::AddressMap* address_map) const;
  void ProcessJumpTable(const JumpTableCandidate& table,
                        core::AddressMap* address_map,
                        std::set<uint32_t>* discovered_entry_points);

  // Helper methods
  bool IsLikelyCodePointer(uint16_t address) const;
  bool IsLikelyCode(uint32_t address, size_t length) const;
  bool IsValidAddress(uint32_t address) const;

 private:
  cpu::CpuPlugin* cpu_;
  const core::Binary* binary_;

  // Constants
  static constexpr size_t kMinJumpTableEntries = 3;
  static constexpr size_t kMaxJumpTableEntries = 256;
  static constexpr float kMinConfidence = 0.6f;
};

}  // namespace analysis
}  // namespace sourcerer

#endif  // SOURCERER_ANALYSIS_STRATEGIES_JUMP_TABLE_DETECTOR_H_
