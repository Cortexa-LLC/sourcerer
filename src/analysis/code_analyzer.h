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

  // Set maximum number of instructions to analyze (safety limit)
  void SetMaxInstructions(size_t max) { max_instructions_ = max; }

  // Get statistics
  size_t GetInstructionCount() const { return instruction_count_; }
  size_t GetCodeBytes() const { return code_bytes_; }
  size_t GetDataBytes() const { return data_bytes_; }

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

  // Second pass: Reclassify CODE regions that look like data
  void ReclassifyDataRegions(core::AddressMap* address_map);

  // Check if a CODE region looks more like data than code
  bool LooksLikeData(uint32_t start_address, uint32_t end_address) const;

  // Calculate percentage of printable ASCII bytes in a region
  float CalculatePrintablePercentage(uint32_t start, uint32_t end) const;
};

}  // namespace analysis
}  // namespace sourcerer

#endif  // SOURCERER_ANALYSIS_CODE_ANALYZER_H_
