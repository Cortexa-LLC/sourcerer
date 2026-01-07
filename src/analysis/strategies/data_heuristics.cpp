// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "analysis/strategies/data_heuristics.h"

#include <algorithm>

#include "core/constants.h"

namespace sourcerer {
namespace analysis {

DataHeuristics::DataHeuristics(const core::Binary* binary)
    : binary_(binary) {}

bool DataHeuristics::LooksLikeData(uint32_t start_address, uint32_t end_address) const {
  uint32_t region_size = end_address - start_address + 1;

  // Skip small regions
  if (region_size < constants::kMinDataRegionSize) {
    return false;
  }

  // High printable percentage suggests text data
  float printable_pct = CalculatePrintablePercentage(start_address, end_address);
  return printable_pct > constants::kPrintableThresholdHigh;
}

int DataHeuristics::CountDataHeuristics(uint32_t start, uint32_t end) const {
  int count = 0;

  // Heuristic 1: High printable percentage (>90%)
  float printable_pct = CalculatePrintablePercentage(start, end);
  if (printable_pct > constants::kPrintableThresholdHigh) {
    count++;
  }

  // Heuristic 2: Long consecutive printable (24+ chars)
  if (HasLongPrintableSequence(start, end)) {
    count++;
  }

  // Heuristic 3: Null-terminated strings
  if (HasNullTerminatedStrings(start, end)) {
    count++;
  }

  // Heuristic 4: Repeated identical bytes
  if (HasRepeatedBytes(start, end)) {
    count++;
  }

  // Heuristic 5: Address-like byte pairs
  if (HasAddressLikePairs(start, end)) {
    count++;
  }

  // Heuristic 6: Repeated identical instructions (graphics data)
  if (HasRepeatedInstructions(start, end)) {
    count++;
  }

  // Heuristic 7: High illegal opcode density
  if (HasHighIllegalDensity(start, end)) {
    count++;
  }

  return count;
}

float DataHeuristics::CalculatePrintablePercentage(uint32_t start, uint32_t end) const {
  if (end <= start) return 0.0f;

  int printable_count = 0;
  int total_count = 0;

  for (uint32_t addr = start; addr <= end; ++addr) {
    const uint8_t* byte = binary_->GetPointer(addr);
    if (!byte) break;

    total_count++;
    uint8_t low = (*byte) & constants::kAsciiMask;  // Strip high bit
    if (low >= constants::kPrintableMin && low < constants::kPrintableMax) {
      printable_count++;
    }
  }

  if (total_count == 0) return 0.0f;
  return static_cast<float>(printable_count) / static_cast<float>(total_count);
}

bool DataHeuristics::HasLongPrintableSequence(uint32_t start, uint32_t end) const {
  size_t max_consecutive = 0;
  size_t current_consecutive = 0;

  for (uint32_t addr = start; addr <= end; ++addr) {
    const uint8_t* byte = binary_->GetPointer(addr);
    if (!byte) break;

    uint8_t low = (*byte) & constants::kAsciiMask;
    if (low >= constants::kPrintableMin && low < constants::kPrintableMax) {
      current_consecutive++;
      max_consecutive = std::max(max_consecutive, current_consecutive);
    } else {
      current_consecutive = 0;
    }
  }

  return max_consecutive >= constants::kMinPrintableSequenceLength;
}

bool DataHeuristics::HasNullTerminatedStrings(uint32_t start, uint32_t end) const {
  int null_terminated_strings = 0;

  for (uint32_t addr = start; addr < end; ++addr) {
    const uint8_t* byte = binary_->GetPointer(addr);
    if (!byte || *byte != 0x00) continue;

    // Check if preceded by printable chars
    int printable_before = 0;
    for (int i = 1; i <= constants::kStringLookbackDistance && addr >= start + i; ++i) {
      const uint8_t* prev = binary_->GetPointer(addr - i);
      if (!prev) break;
      uint8_t low = (*prev) & constants::kAsciiMask;
      if (low >= constants::kPrintableMin && low < constants::kPrintableMax) {
        printable_before++;
      } else {
        break;
      }
    }

    if (printable_before >= constants::kMinPrintableBeforeNull) {
      null_terminated_strings++;
    }
  }

  return null_terminated_strings >= constants::kMinNullTerminatedStrings;
}

bool DataHeuristics::HasRepeatedBytes(uint32_t start, uint32_t end) const {
  int max_same = 0;
  int current_same = 1;
  uint8_t prev_byte = 0;

  for (uint32_t addr = start; addr <= end; ++addr) {
    const uint8_t* byte = binary_->GetPointer(addr);
    if (!byte) break;

    if (addr == start) {
      prev_byte = *byte;
    } else {
      if (*byte == prev_byte) {
        current_same++;
        max_same = std::max(max_same, current_same);
      } else {
        current_same = 1;
        prev_byte = *byte;
      }
    }
  }

  return max_same >= constants::kMinRepeatedByteCount;
}

bool DataHeuristics::HasAddressLikePairs(uint32_t start, uint32_t end) const {
  uint32_t region_size = end - start + 1;
  if (region_size < constants::kMinRegionSizeForAddressPairs) return false;

  uint32_t address_like_pairs = 0;
  for (uint32_t addr = start; addr < end - 1; addr += 2) {
    const uint8_t* lo = binary_->GetPointer(addr);
    const uint8_t* hi = binary_->GetPointer(addr + 1);
    if (!lo || !hi) continue;

    uint16_t potential_addr = (*lo) | ((*hi) << 8);
    if (potential_addr >= constants::kAddressUpperThreshold ||
        potential_addr < constants::kAddressLowerThreshold) {
      address_like_pairs++;
    }
  }

  return address_like_pairs >= (region_size / constants::kAddressPairProportionDenom);
}

bool DataHeuristics::HasRepeatedInstructions(uint32_t start, uint32_t end) const {
  // Detect repeated identical instruction patterns (like graphics data)
  int max_repeat = 0;
  int current_repeat = 1;

  for (uint32_t addr = start; addr < end - 3; addr += 2) {
    const uint8_t* curr = binary_->GetPointer(addr);
    const uint8_t* next = binary_->GetPointer(addr + 2);

    if (!curr || !next) break;

    if (curr[0] == next[0] && curr[1] == next[1]) {
      current_repeat++;
      max_repeat = std::max(max_repeat, current_repeat);
    } else {
      current_repeat = 1;
    }
  }

  return max_repeat >= constants::kMinRepeatedInstructionPatterns;
}

bool DataHeuristics::HasHighIllegalDensity(uint32_t start, uint32_t end) const {
  // Check if region has many illegal opcodes (suggests data, not code)
  // This is a simple heuristic - could be improved with CPU-specific knowledge

  uint32_t region_size = end - start + 1;
  if (region_size < constants::kMinRegionSizeForIllegalCheck) return false;

  // Count bytes that look like illegal/uncommon opcodes
  // For 6502/6809, certain byte values are illegal or very rare
  uint32_t suspicious_count = 0;
  for (uint32_t addr = start; addr <= end; ++addr) {
    const uint8_t* byte = binary_->GetPointer(addr);
    if (!byte) break;

    // These are often illegal or very rare opcodes on 6502/6809
    uint8_t b = *byte;
    if (b == 0xFF || b == 0xFE || b == 0x00 ||
        (b >= 0x02 && b <= 0x03) || (b >= 0x0B && b <= 0x0C)) {
      suspicious_count++;
    }
  }

  return suspicious_count >= (region_size / constants::kSuspiciousOpcodeProportionDenom);
}

}  // namespace analysis
}  // namespace sourcerer
