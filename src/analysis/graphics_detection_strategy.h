// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_ANALYSIS_GRAPHICS_DETECTION_STRATEGY_H_
#define SOURCERER_ANALYSIS_GRAPHICS_DETECTION_STRATEGY_H_

#include <cstdint>

#include "core/binary.h"

namespace sourcerer {
namespace analysis {

/**
 * Graphics Detection Strategy
 *
 * Provides heuristics for detecting graphics data (bitmaps, sprites, character
 * data) within binary files. Uses multiple independent signals:
 * - Shannon entropy analysis (bitmap randomness)
 * - Byte alignment patterns (8/16 byte boundaries for character data)
 * - Platform-specific graphics memory regions (Apple II, CoCo)
 * - Sprite/character bit patterns (sparse pixels, background bytes)
 *
 * Graphics data has distinct characteristics:
 * - Medium entropy (3.5-7.0) - not too uniform, not too random
 * - Aligned on character/sprite boundaries (8, 16, 32 bytes)
 * - Sparse bit patterns (few bits set per byte for sprites)
 * - Located in known graphics regions (platform-dependent)
 *
 * References:
 * - WP-01: CodeAnalyzer refactoring into strategy classes
 * - CLAUDE.md: Architecture - Graphics pattern detection
 */
class GraphicsDetectionStrategy {
 public:
  /**
   * Construct graphics detection strategy.
   *
   * @param binary Pointer to binary being analyzed (non-owning)
   */
  explicit GraphicsDetectionStrategy(const core::Binary* binary);

  /**
   * Check if region has bitmap entropy characteristics.
   *
   * Bitmap graphics typically has Shannon entropy between 3.5 and 7.0:
   * - Too low (< 3.5): Uniform data or simple code
   * - Good range (3.5-7.0): Bitmap graphics, sprite data
   * - Too high (> 7.0): Compressed or encrypted data
   *
   * @param start Start of region
   * @param end End of region (inclusive)
   * @return true if entropy suggests bitmap graphics
   */
  bool HasBitmapEntropy(uint32_t start, uint32_t end) const;

  /**
   * Check if region is aligned on graphics boundaries.
   *
   * Character and sprite data is typically aligned:
   * - Character data: 8-byte aligned (8 rows per character)
   * - Sprite data: 8, 16, or 32 byte aligned
   *
   * Also checks for repeating patterns at 8-byte intervals which
   * is characteristic of character/sprite data.
   *
   * @param start Start of region
   * @param end End of region (inclusive)
   * @return true if aligned on graphics boundaries
   */
  bool HasByteAlignment(uint32_t start, uint32_t end) const;

  /**
   * Check if region is in known platform graphics memory.
   *
   * Platform-specific graphics regions:
   * - Apple II Hi-Res: $2000-$3FFF (page 1), $4000-$5FFF (page 2)
   * - CoCo PMODE: $0600-$1FFF (typical locations)
   *
   * @param start Start of region
   * @param end End of region (inclusive)
   * @return true if in known graphics region
   */
  bool IsInGraphicsRegion(uint32_t start, uint32_t end) const;

  /**
   * Check for sprite/character data patterns.
   *
   * Sprite data has distinctive characteristics:
   * - Mix of zero/FF bytes (20-60%) for background/transparent areas
   * - Sparse bytes (10-40%) with 1-3 bits set for pixels
   * - Minimum size 64 bytes (8x8 sprite minimum)
   *
   * @param start Start of region
   * @param end End of region (inclusive)
   * @return true if matches sprite/character patterns
   */
  bool HasSpritePatterns(uint32_t start, uint32_t end) const;

  /**
   * Calculate Shannon entropy of data.
   *
   * Shannon entropy measures randomness/information density:
   * - 0.0: Completely uniform (all same byte)
   * - 8.0: Maximum randomness (perfect distribution)
   *
   * Formula: H = -Σ(p(i) * log2(p(i))) for i in 0..255
   *
   * @param data Pointer to data buffer
   * @param length Length of data in bytes
   * @return Shannon entropy (0.0 to 8.0)
   */
  float CalculateEntropy(const uint8_t* data, size_t length) const;

 private:
  const core::Binary* binary_;  // Non-owning pointer to binary

  // Helper: Check if address is valid and within binary bounds
  bool IsValidAddress(uint32_t address) const;
};

}  // namespace analysis
}  // namespace sourcerer

#endif  // SOURCERER_ANALYSIS_GRAPHICS_DETECTION_STRATEGY_H_
