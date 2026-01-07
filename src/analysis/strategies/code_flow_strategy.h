// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_ANALYSIS_STRATEGIES_CODE_FLOW_STRATEGY_H_
#define SOURCERER_ANALYSIS_STRATEGIES_CODE_FLOW_STRATEGY_H_

#include <cstdint>
#include <map>
#include <set>

#include "core/address_map.h"
#include "core/binary.h"
#include "core/instruction.h"
#include "cpu/cpu_plugin.h"

namespace sourcerer {
namespace analysis {

// Forward declarations for strategy dependencies
class MisalignmentResolver;
class EntryPointDiscoveryStrategy;
class InlineDataScanner;

// Strategy for recursive code flow analysis
// Traverses code following branches, jumps, and calls recursively
// Extracted from CodeAnalyzer to follow Single Responsibility Principle
class CodeFlowStrategy {
 public:
  CodeFlowStrategy(cpu::CpuPlugin* cpu,
                  const core::Binary* binary,
                  MisalignmentResolver* misalignment_resolver,
                  EntryPointDiscoveryStrategy* entry_point_discovery,
                  InlineDataScanner* inline_data_scanner);

  // Main recursive analysis method
  void AnalyzeRecursively(uint32_t address,
                         core::AddressMap* address_map,
                         std::map<uint32_t, core::Instruction>* instruction_cache,
                         std::set<uint32_t>* lea_targets,
                         int* code_bytes_discovered,
                         size_t* instruction_count,
                         int depth);

  // Run a single analysis pass
  int RunAnalysisPass(core::AddressMap* address_map,
                     const std::set<uint32_t>& entry_points,
                     const std::set<uint32_t>& discovered_entry_points,
                     std::map<uint32_t, core::Instruction>* instruction_cache,
                     std::set<uint32_t>* lea_targets,
                     int* code_bytes_discovered,
                     size_t* instruction_count,
                     int passes_completed);

  // Clear visited markers
  void ClearVisited();

  // Check if address was visited
  bool WasVisited(uint32_t address) const;

  // Helper to check if address is valid
  bool IsValidAddress(uint32_t address) const;

 private:
  cpu::CpuPlugin* cpu_;
  const core::Binary* binary_;
  MisalignmentResolver* misalignment_resolver_;
  EntryPointDiscoveryStrategy* entry_point_discovery_;
  InlineDataScanner* inline_data_scanner_;

  // Visited tracking for recursive analysis
  std::set<uint32_t> visited_recursive_;
};

}  // namespace analysis
}  // namespace sourcerer

#endif  // SOURCERER_ANALYSIS_STRATEGIES_CODE_FLOW_STRATEGY_H_
