// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_ANALYSIS_STRATEGIES_RECLASSIFICATION_STRATEGY_H_
#define SOURCERER_ANALYSIS_STRATEGIES_RECLASSIFICATION_STRATEGY_H_

#include <cstdint>
#include <map>
#include <set>

#include "analysis/strategies/data_heuristics.h"
#include "core/address_map.h"
#include "core/binary.h"
#include "core/instruction.h"
#include "cpu/cpu_plugin.h"

namespace sourcerer {
namespace analysis {

// Strategy for reclassifying CODE regions that are actually DATA
// Runs after initial analysis to fix misclassifications
// Extracted from CodeAnalyzer to follow Single Responsibility Principle
class ReclassificationStrategy {
 public:
  ReclassificationStrategy(cpu::CpuPlugin* cpu,
                          const core::Binary* binary,
                          DataHeuristics* data_heuristics);

  // Main reclassification methods
  void ReclassifyAfterComputedJumps(
      core::AddressMap* address_map,
      const std::set<uint32_t>& entry_points);

  void ReclassifyMixedCodeDataRegions(
      core::AddressMap* address_map,
      std::map<uint32_t, core::Instruction>* instruction_cache,
      std::set<uint32_t>* visited_recursive);

  void ReclassifyDataRegions(
      core::AddressMap* address_map,
      const std::set<uint32_t>& entry_points);

  // Helper methods
  int CountXrefsInRange(core::AddressMap* address_map,
                       uint32_t start,
                       uint32_t end) const;

  bool IsValidAddress(uint32_t address) const;

 private:
  cpu::CpuPlugin* cpu_;
  const core::Binary* binary_;
  DataHeuristics* data_heuristics_;
};

}  // namespace analysis
}  // namespace sourcerer

#endif  // SOURCERER_ANALYSIS_STRATEGIES_RECLASSIFICATION_STRATEGY_H_
