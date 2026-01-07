// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_ANALYSIS_STRATEGIES_GRAPHICS_DETECTOR_H_
#define SOURCERER_ANALYSIS_STRATEGIES_GRAPHICS_DETECTOR_H_

#include <cstdint>

#include "core/binary.h"

namespace sourcerer {
namespace analysis {

// Strategy for detecting graphics/bitmap data patterns
// Extracted from CodeAnalyzer to follow Single Responsibility Principle
class GraphicsDetector {
 public:
  explicit GraphicsDetector(const core::Binary* binary);

  // Main interface - check if region looks like graphics
  bool LooksLikeGraphics(uint32_t start, uint32_t end) const;

  // Individual graphics heuristics
  bool HasBitmapEntropy(uint32_t start, uint32_t end) const;
  bool HasByteAlignment(uint32_t start, uint32_t end) const;
  bool IsInGraphicsRegion(uint32_t start, uint32_t end) const;
  bool HasSpritePatterns(uint32_t start, uint32_t end) const;

  // Entropy calculation helper
  float CalculateEntropy(const uint8_t* data, size_t length) const;

 private:
  const core::Binary* binary_;
};

}  // namespace analysis
}  // namespace sourcerer

#endif  // SOURCERER_ANALYSIS_STRATEGIES_GRAPHICS_DETECTOR_H_
