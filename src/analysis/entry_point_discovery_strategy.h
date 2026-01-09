// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_ANALYSIS_ENTRY_POINT_DISCOVERY_STRATEGY_H_
#define SOURCERER_ANALYSIS_ENTRY_POINT_DISCOVERY_STRATEGY_H_

#include <cstdint>
#include <set>

#include "core/address_map.h"
#include "core/binary.h"
#include "cpu/cpu_plugin.h"

namespace sourcerer {
namespace analysis {

/**
 * Entry Point Discovery Strategy
 *
 * Discovers code entry points through multiple heuristics:
 * - Interrupt vector scanning (CPU-specific)
 * - Subroutine prologue pattern matching (stack frame setup)
 * - Platform-specific entry points (CoCo cartridge headers)
 *
 * This strategy enables discovering code that isn't reachable from
 * the initial entry point through standard flow analysis.
 *
 * ## Discovery Methods
 *
 * 1. **Interrupt Vectors**: Scans CPU interrupt vectors for code pointers
 * 2. **Subroutine Patterns**: Looks for PSHS/PHP instructions (frame setup)
 * 3. **Platform-Specific**: Scans known entry point locations (cartridges)
 *
 * Extracted from CodeAnalyzer to follow Single Responsibility Principle (WP-01 Phase 4).
 *
 * References:
 * - WP-01: CodeAnalyzer refactoring into strategy classes
 * - CLAUDE.md: Architecture - Entry point discovery
 */
class EntryPointDiscoveryStrategy {
 public:
  /**
   * Construct entry point discovery strategy.
   *
   * @param cpu CPU plugin for architecture-specific discovery
   * @param binary Binary being analyzed (non-owning)
   */
  EntryPointDiscoveryStrategy(cpu::CpuPlugin* cpu, const core::Binary* binary);

  /**
   * Discover entry points using all available heuristics.
   *
   * Orchestrates multiple discovery methods:
   * 1. Scan interrupt vectors (CPU-specific)
   * 2. Scan for subroutine patterns (PSHS/PHP)
   * 3. Scan platform-specific locations (CoCo cartridge)
   *
   * Discovered entry points are added to the provided sets for
   * subsequent analysis by CodeAnalyzer.
   *
   * @param address_map Current address map (for code/data context)
   * @param discovered_entry_points Set to add discovered entry points to
   * @param lea_targets Set to add LEA target addresses to (potential data)
   */
  void DiscoverEntryPoints(core::AddressMap* address_map,
                          std::set<uint32_t>* discovered_entry_points,
                          std::set<uint32_t>* lea_targets);

  /**
   * Scan CPU interrupt vectors for code pointers.
   *
   * Uses CPU plugin to get interrupt vector locations and reads
   * target addresses. Validates targets and adds them as entry points.
   *
   * CPU-agnostic design: Uses CpuPlugin::GetInterruptVectors() and
   * ReadVectorTarget() for architecture-independent discovery.
   *
   * @param discovered_entry_points Set to add discovered entry points to
   */
  void ScanInterruptVectors(std::set<uint32_t>* discovered_entry_points);

  /**
   * Scan for subroutine prologue patterns.
   *
   * Searches DATA/UNKNOWN regions for patterns that look like subroutine
   * entry points:
   * - PSHS instruction (6809 stack frame setup)
   * - PHP/PHA instructions (6502 stack frame setup)
   * - Valid instruction sequences following the prologue
   *
   * Uses CPU plugin's LooksLikeSubroutineStart() and IsLikelyCode()
   * for architecture-specific pattern matching.
   *
   * @param address_map Current address map
   * @param discovered_entry_points Set to add discovered entry points to
   * @param lea_targets Set to add LEA target addresses to (potential data)
   */
  void ScanForSubroutinePatterns(core::AddressMap* address_map,
                                std::set<uint32_t>* discovered_entry_points,
                                std::set<uint32_t>* lea_targets);

  /**
   * Check if address looks like subroutine entry point.
   *
   * Delegates to CPU plugin for architecture-specific detection.
   * Common patterns:
   * - 6809: PSHS (stack frame setup)
   * - 6502: PHP/PHA (save registers)
   *
   * @param address Address to check
   * @return true if looks like subroutine start
   */
  bool LooksLikeSubroutineStart(uint32_t address) const;

  /**
   * Check if address looks like valid code.
   *
   * Delegates to CPU plugin for architecture-specific heuristics.
   * Examines instruction sequence validity, common patterns, etc.
   *
   * @param address Address to check
   * @param scan_length Number of bytes to examine (default: 16)
   * @return true if likely to be code
   */
  bool IsLikelyCode(uint32_t address, size_t scan_length = 16) const;

  /**
   * Scan CoCo cartridge-specific entry points.
   *
   * CoCo cartridges have standard entry points at known locations:
   * - $C000: Cartridge auto-start
   * - $C002: Secondary entry point
   * - Other platform-specific locations
   *
   * Only applicable when analyzing CoCo binaries.
   *
   * @param discovered_entry_points Set to add discovered entry points to
   */
  void ScanCoCoCartridgeEntryPoints(std::set<uint32_t>* discovered_entry_points);

  /**
   * Scan CoCo standard entry points.
   *
   * CoCo standard entry points include:
   * - BASIC cartridge ROM locations
   * - Common function entry addresses
   *
   * @param discovered_entry_points Set to add discovered entry points to
   */
  void ScanCoCoStandardEntryPoints(std::set<uint32_t>* discovered_entry_points);

  /**
   * Check if address is in CoCo cartridge space.
   *
   * CoCo cartridge space: $C000-$FEFF
   *
   * @param address Address to check
   * @return true if in cartridge space
   */
  bool IsCoCoCartridgeSpace(uint32_t address) const;

  /**
   * Check if address has CoCo cartridge preamble.
   *
   * CoCo cartridges often have a signature byte sequence
   * (e.g., 'DK' $44 $4B for disk BASIC cartridge).
   *
   * @param address Address to check
   * @return true if has valid preamble
   */
  bool HasCoCoPreamble(uint32_t address) const;

 private:
  cpu::CpuPlugin* cpu_;         // CPU plugin for arch-specific discovery
  const core::Binary* binary_;  // Binary being analyzed (non-owning)

  // Helper: Check if address is valid and within binary bounds
  bool IsValidAddress(uint32_t address) const;
};

}  // namespace analysis
}  // namespace sourcerer

#endif  // SOURCERER_ANALYSIS_ENTRY_POINT_DISCOVERY_STRATEGY_H_
