// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_ANALYSIS_STRATEGIES_ENTRY_POINT_DISCOVERY_STRATEGY_H_
#define SOURCERER_ANALYSIS_STRATEGIES_ENTRY_POINT_DISCOVERY_STRATEGY_H_

#include <cstdint>
#include <set>

#include "core/address_map.h"
#include "core/binary.h"
#include "cpu/cpu_plugin.h"

namespace sourcerer {
namespace analysis {

// Strategy for discovering entry points beyond the initial entry point
// Scans interrupt vectors, subroutine patterns, and platform-specific locations
// Extracted from CodeAnalyzer to follow Single Responsibility Principle
class EntryPointDiscoveryStrategy {
 public:
  EntryPointDiscoveryStrategy(cpu::CpuPlugin* cpu, const core::Binary* binary);

  // Main interface - discover all entry points
  void DiscoverEntryPoints(core::AddressMap* address_map,
                          std::set<uint32_t>* discovered_entry_points);

  // Individual discovery methods
  void ScanInterruptVectors(std::set<uint32_t>* discovered_entry_points);
  void ScanForSubroutinePatterns(core::AddressMap* address_map,
                                std::set<uint32_t>* discovered_entry_points);

  // Helper methods
  bool LooksLikeSubroutineStart(uint32_t address) const;
  bool IsLikelyCode(uint32_t address, size_t scan_length = 16) const;
  bool IsValidAddress(uint32_t address) const;

  // CoCo-specific methods
  void ScanCoCoCartridgeEntryPoints(std::set<uint32_t>* discovered_entry_points);
  void ScanCoCoStandardEntryPoints(std::set<uint32_t>* discovered_entry_points);
  bool IsCoCoCartridgeSpace(uint32_t address) const;
  bool HasCoCoPreamble(uint32_t address) const;

  // LEA target tracking
  void RecordLeaTarget(uint32_t address);
  bool IsLeaTarget(uint32_t address) const;
  const std::set<uint32_t>& GetLeaTargets() const;

 private:
  cpu::CpuPlugin* cpu_;
  const core::Binary* binary_;

  // LEA/LEAX/LEAY target addresses (potential data, not code)
  std::set<uint32_t> lea_targets_;

  // Constants
  static constexpr int kSampleStride = 4;  // Check every 4 bytes
};

}  // namespace analysis
}  // namespace sourcerer

#endif  // SOURCERER_ANALYSIS_STRATEGIES_ENTRY_POINT_DISCOVERY_STRATEGY_H_
