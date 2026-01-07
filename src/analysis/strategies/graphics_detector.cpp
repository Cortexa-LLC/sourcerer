// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "analysis/strategies/graphics_detector.h"

#include <cmath>

namespace sourcerer {
namespace analysis {

GraphicsDetector::GraphicsDetector(const core::Binary* binary)
    : binary_(binary) {}

bool GraphicsDetector::LooksLikeGraphics(uint32_t start, uint32_t end) const {
  // Check multiple graphics heuristics
  int matches = 0;

  if (HasBitmapEntropy(start, end)) matches++;
  if (HasByteAlignment(start, end)) matches++;
  if (IsInGraphicsRegion(start, end)) matches++;
  if (HasSpritePatterns(start, end)) matches++;

  // Require at least 2 matches to classify as graphics
  return matches >= 2;
}

float GraphicsDetector::CalculateEntropy(const uint8_t* data, size_t length) const {
  if (length == 0) return 0.0f;

  // Count byte frequency
  int freq[256] = {0};
  for (size_t i = 0; i < length; ++i) {
    freq[data[i]]++;
  }

  // Calculate Shannon entropy
  float entropy = 0.0f;
  for (int i = 0; i < 256; ++i) {
    if (freq[i] > 0) {
      float prob = static_cast<float>(freq[i]) / static_cast<float>(length);
      entropy -= prob * std::log2(prob);
    }
  }

  return entropy;
}

bool GraphicsDetector::HasBitmapEntropy(uint32_t start, uint32_t end) const {
  uint32_t region_size = end - start + 1;
  if (region_size < 16) return false;

  const uint8_t* data = binary_->GetPointer(start);
  if (!data) return false;

  float entropy = CalculateEntropy(data, region_size);

  // Graphics bitmap data typically has entropy between 3.5 and 7.0
  // - Too low (< 3.5): probably code or uniform data
  // - Good range (3.5-7.0): bitmap graphics, sprite data
  // - Too high (> 7.0): compressed or encrypted data
  return (entropy >= 3.5f && entropy <= 7.0f);
}

bool GraphicsDetector::HasByteAlignment(uint32_t start, uint32_t end) const {
  uint32_t region_size = end - start + 1;

  // Check if region is aligned on common graphics boundaries
  // Character data: 8-byte aligned (8 rows per character)
  // Sprite data: Often 8, 16, or 32 byte aligned
  bool is_8_aligned = ((start % 8) == 0) && ((region_size % 8) == 0);
  bool is_16_aligned = ((start % 16) == 0) && ((region_size % 16) == 0);

  if (!is_8_aligned && !is_16_aligned) {
    return false;
  }

  // Additionally check for repeating patterns at 8-byte intervals
  // (typical for character/sprite data)
  if (region_size >= 16) {
    const uint8_t* data = binary_->GetPointer(start);
    if (!data) return false;

    int pattern_matches = 0;
    for (uint32_t offset = 0; offset < 8 && offset < region_size - 8; ++offset) {
      bool has_pattern = true;
      for (uint32_t i = offset + 8; i < region_size; i += 8) {
        if (data[offset] != data[i]) {
          has_pattern = false;
          break;
        }
      }
      if (has_pattern) {
        pattern_matches++;
      }
    }

    // If we find repeating patterns, likely graphics
    if (pattern_matches >= 2) {
      return true;
    }
  }

  return is_8_aligned || is_16_aligned;
}

bool GraphicsDetector::IsInGraphicsRegion(uint32_t start, uint32_t end) const {
  // Platform-specific graphics memory regions

  // Apple II Hi-Res graphics pages
  // Page 1: $2000-$3FFF (8192 bytes)
  // Page 2: $4000-$5FFF (8192 bytes)
  if (start >= 0x2000 && end <= 0x3FFF) return true;
  if (start >= 0x4000 && end <= 0x5FFF) return true;

  // CoCo PMODE graphics pages (typical locations)
  // PMODE 4: $0E00-$1FFF (when not in all-RAM mode)
  // High-res graphics typically at $0600-$1FFF or custom locations
  if (start >= 0x0600 && end <= 0x1FFF) return true;

  return false;
}

bool GraphicsDetector::HasSpritePatterns(uint32_t start, uint32_t end) const {
  uint32_t region_size = end - start + 1;
  if (region_size < 64) return false;  // Sprites usually >= 8x8 = 64 bytes minimum

  const uint8_t* data = binary_->GetPointer(start);
  if (!data) return false;

  // Look for patterns typical of sprite/character data:
  // 1. Blocks of 8 or 16 bytes (sprite rows)
  // 2. Some bytes all zeros (transparent/background)
  // 3. Some bytes with bit patterns (pixels)

  int zero_byte_count = 0;
  int sparse_byte_count = 0;  // Bytes with 1-3 bits set

  for (uint32_t i = 0; i < region_size; ++i) {
    uint8_t byte = data[i];
    if (byte == 0x00 || byte == 0xFF) {
      zero_byte_count++;
    } else {
      // Count bits set
      int bits_set = 0;
      for (int bit = 0; bit < 8; ++bit) {
        if (byte & (1 << bit)) bits_set++;
      }

      if (bits_set >= 1 && bits_set <= 3) {
        sparse_byte_count++;
      }
    }
  }

  // Sprite data usually has:
  // - 20-60% zero bytes (transparent areas)
  // - 10-40% sparse bytes (edge pixels)
  float zero_pct = static_cast<float>(zero_byte_count) / static_cast<float>(region_size);
  float sparse_pct = static_cast<float>(sparse_byte_count) / static_cast<float>(region_size);

  return (zero_pct >= 0.20f && zero_pct <= 0.60f) ||
         (sparse_pct >= 0.10f && sparse_pct <= 0.40f);
}

}  // namespace analysis
}  // namespace sourcerer
