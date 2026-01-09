// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_ANALYSIS_DATA_HEURISTICS_ENGINE_H_
#define SOURCERER_ANALYSIS_DATA_HEURISTICS_ENGINE_H_

#include <cstdint>

#include "core/binary.h"
#include "core/address_map.h"

namespace sourcerer {
namespace analysis {

/**
 * Data Heuristics Engine
 *
 * Provides heuristics for detecting DATA regions within CODE using multiple
 * independent signals:
 * - Printable ASCII sequences (text strings)
 * - Null-terminated strings
 * - Repeated byte patterns (bitmaps, fill patterns)
 * - Address-like 16-bit pairs (jump tables, vectors)
 * - Repeated instruction patterns (suggests data misinterpreted as code)
 * - High illegal instruction density
 *
 * Uses conservative multi-heuristic approach: requires MIN_HEURISTIC_MATCHES
 * independent signals before classifying a region as DATA to avoid false
 * positives that would corrupt valid code.
 *
 * References:
 * - WP-01: CodeAnalyzer refactoring into strategy classes
 * - CLAUDE.md: Architecture - Data detection heuristics
 */
class DataHeuristicsEngine {
 public:
  /**
   * Construct data heuristics engine.
   *
   * @param binary Pointer to binary being analyzed (non-owning)
   */
  explicit DataHeuristicsEngine(const core::Binary* binary);

  /**
   * Check if a CODE region looks more like data than code.
   *
   * Applies multiple independent heuristics and requires at least
   * MIN_HEURISTIC_MATCHES to match before returning true.
   *
   * @param start_address Start of region to check
   * @param end_address End of region (inclusive)
   * @return true if region matches enough data heuristics
   */
  bool LooksLikeData(uint32_t start_address, uint32_t end_address) const;

  /**
   * Count how many data heuristics match for a region.
   *
   * Returns count of independent signals that suggest this is DATA:
   * - High printable ASCII percentage (>90%)
   * - Long printable sequences (>8 bytes)
   * - Null-terminated strings
   * - Repeated bytes
   * - Address-like 16-bit pairs
   * - Repeated instruction patterns
   * - High illegal instruction density
   *
   * @param start Start of region
   * @param end End of region (inclusive)
   * @return Number of matching heuristics (0-7)
   */
  int CountDataHeuristics(uint32_t start, uint32_t end) const;

  /**
   * Calculate percentage of printable ASCII bytes in region.
   *
   * Printable ASCII: 0x20-0x7E plus newline (0x0A) and carriage return (0x0D).
   *
   * @param start Start of region
   * @param end End of region (inclusive)
   * @return Percentage of printable bytes (0.0 to 1.0)
   */
  float CalculatePrintablePercentage(uint32_t start, uint32_t end) const;

  /**
   * Check for long printable ASCII sequences.
   *
   * Looks for sequences of 8+ consecutive printable characters,
   * which strongly suggests text strings rather than code.
   *
   * @param start Start of region
   * @param end End of region (inclusive)
   * @return true if region contains printable sequence ≥8 bytes
   */
  bool HasLongPrintableSequence(uint32_t start, uint32_t end) const;

  /**
   * Check for null-terminated strings.
   *
   * Looks for sequences of printable ASCII followed by 0x00,
   * which is common in string tables and message data.
   *
   * @param start Start of region
   * @param end End of region (inclusive)
   * @return true if region contains null-terminated string
   */
  bool HasNullTerminatedStrings(uint32_t start, uint32_t end) const;

  /**
   * Check for repeated byte patterns.
   *
   * Looks for same byte repeated 4+ times consecutively,
   * which is common in graphics data, fill patterns, and padding.
   *
   * @param start Start of region
   * @param end End of region (inclusive)
   * @return true if region contains repeated byte pattern
   */
  bool HasRepeatedBytes(uint32_t start, uint32_t end) const;

  /**
   * Check for address-like 16-bit pairs.
   *
   * Looks for little-endian addresses that point to valid binary ranges,
   * suggesting jump tables, vector tables, or pointer arrays.
   *
   * @param start Start of region
   * @param end End of region (inclusive)
   * @return true if region contains address-like pairs
   */
  bool HasAddressLikePairs(uint32_t start, uint32_t end) const;

  /**
   * Check for repeated instruction patterns.
   *
   * If the same instruction appears 4+ times consecutively, this suggests
   * data that happens to decode as valid instructions (phantom code).
   *
   * @param start Start of region
   * @param end End of region (inclusive)
   * @return true if region has repeated instruction patterns
   */
  bool HasRepeatedInstructions(uint32_t start, uint32_t end) const;

  /**
   * Check for high density of illegal instructions.
   *
   * If >30% of bytes decode as illegal/invalid instructions, this suggests
   * data rather than code.
   *
   * @param start Start of region
   * @param end End of region (inclusive)
   * @return true if region has high illegal instruction density
   */
  bool HasHighIllegalDensity(uint32_t start, uint32_t end) const;

  /**
   * Count cross-references within a region.
   *
   * Helper method that counts how many addresses in range have incoming
   * cross-references (branches/calls from other code). Used by CodeAnalyzer
   * to avoid reclassifying regions that are referenced by valid code.
   *
   * @param address_map Address map with cross-reference information
   * @param start Start of region
   * @param end End of region (inclusive)
   * @return Number of addresses with incoming xrefs
   */
  int CountXrefsInRange(core::AddressMap* address_map,
                        uint32_t start, uint32_t end) const;

  // Configuration constants
  static constexpr size_t MIN_DATA_REGION_SIZE = 16;   // Minimum bytes to check
  static constexpr int MIN_HEURISTIC_MATCHES = 2;      // Require 2+ signals
  static constexpr float PRINTABLE_THRESHOLD_HIGH = 0.90f;  // 90% printable

 private:
  const core::Binary* binary_;  // Non-owning pointer to binary

  // Helper: Check if address is valid and within binary bounds
  bool IsValidAddress(uint32_t address) const;
};

}  // namespace analysis
}  // namespace sourcerer

#endif  // SOURCERER_ANALYSIS_DATA_HEURISTICS_ENGINE_H_
