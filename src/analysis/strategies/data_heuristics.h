// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_ANALYSIS_STRATEGIES_DATA_HEURISTICS_H_
#define SOURCERER_ANALYSIS_STRATEGIES_DATA_HEURISTICS_H_

#include <cstdint>

#include "core/binary.h"
#include "core/constants.h"

namespace sourcerer {
namespace analysis {

// Strategy for detecting data patterns in binary regions
// Extracted from CodeAnalyzer to follow Single Responsibility Principle
class DataHeuristics {
 public:
  explicit DataHeuristics(const core::Binary* binary);

  // Main interface - check if region looks like data
  bool LooksLikeData(uint32_t start_address, uint32_t end_address) const;

  // Count how many data heuristics match (0-7)
  int CountDataHeuristics(uint32_t start, uint32_t end) const;

  // Calculate percentage of printable ASCII bytes
  float CalculatePrintablePercentage(uint32_t start, uint32_t end) const;

  // Individual heuristic methods
  bool HasLongPrintableSequence(uint32_t start, uint32_t end) const;
  bool HasNullTerminatedStrings(uint32_t start, uint32_t end) const;
  bool HasRepeatedBytes(uint32_t start, uint32_t end) const;
  bool HasAddressLikePairs(uint32_t start, uint32_t end) const;
  bool HasRepeatedInstructions(uint32_t start, uint32_t end) const;
  bool HasHighIllegalDensity(uint32_t start, uint32_t end) const;

 private:
  const core::Binary* binary_;

  // Constants (using constants namespace)
  static constexpr size_t kMinDataRegionSize = constants::kMinDataRegionSize;
  static constexpr float kPrintableThresholdHigh = constants::kPrintableThresholdHigh;
};

}  // namespace analysis
}  // namespace sourcerer

#endif  // SOURCERER_ANALYSIS_STRATEGIES_DATA_HEURISTICS_H_
