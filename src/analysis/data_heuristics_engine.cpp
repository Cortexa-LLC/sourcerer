// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "analysis/data_heuristics_engine.h"

#include <algorithm>
#include <cmath>

#include "core/instruction.h"
#include "utils/logger.h"

namespace sourcerer {
namespace analysis {

DataHeuristicsEngine::DataHeuristicsEngine(const core::Binary* binary)
    : binary_(binary) {}

bool DataHeuristicsEngine::IsValidAddress(uint32_t address) const {
  uint32_t start = binary_->load_address();
  uint32_t end = start + binary_->size();
  return address >= start && address < end;
}

bool DataHeuristicsEngine::LooksLikeData(uint32_t start_address,
                                         uint32_t end_address) const {
  if (end_address <= start_address) return false;

  uint32_t region_size = end_address - start_address + 1;

  // Very small regions (< 4 bytes) are hard to determine, assume code
  if (region_size < 4) return false;

  // Calculate percentage of printable ASCII bytes
  float printable_pct = CalculatePrintablePercentage(start_address, end_address);

  // Check for long sequences of consecutive printable bytes (likely strings)
  int max_consecutive_printable = 0;
  int current_consecutive = 0;
  int string_count = 0;  // Count of distinct string-like sequences

  for (uint32_t addr = start_address; addr <= end_address; ++addr) {
    const uint8_t* byte = binary_->GetPointer(addr);
    if (!byte) break;

    uint8_t low = (*byte) & 0x7F;  // Strip high bit
    if (low >= 0x20 && low < 0x7F) {
      current_consecutive++;
      if (current_consecutive > max_consecutive_printable) {
        max_consecutive_printable = current_consecutive;
      }
    } else {
      // If we had a string-like sequence, count it
      if (current_consecutive >= 5) {
        string_count++;
      }
      current_consecutive = 0;
    }
  }

  // Count the last sequence if it ended at the boundary
  if (current_consecutive >= 5) {
    string_count++;
  }

  // Strong indicator: 20+ consecutive printable characters (definitely a string)
  if (max_consecutive_printable >= 20) {
    return true;
  }

  // Medium indicator: 80%+ printable AND 10+ consecutive (likely string)
  if (printable_pct > 0.80f && max_consecutive_printable >= 10) {
    return true;
  }

  // Multiple short strings indicator: 2+ sequences of 5+ printable chars
  if (string_count >= 2 && printable_pct > 0.60f) {
    return true;
  }

  // Check for unlikely instruction patterns
  // Count how many times the same opcode appears consecutively
  int max_same_opcode = 0;
  int current_same_opcode = 1;
  uint8_t prev_opcode = 0;

  for (uint32_t addr = start_address; addr <= end_address; ++addr) {
    const uint8_t* byte = binary_->GetPointer(addr);
    if (!byte) break;

    if (addr == start_address) {
      prev_opcode = *byte;
    } else {
      if (*byte == prev_opcode) {
        current_same_opcode++;
        if (current_same_opcode > max_same_opcode) {
          max_same_opcode = current_same_opcode;
        }
      } else {
        current_same_opcode = 1;
        prev_opcode = *byte;
      }
    }
  }

  // If we have 4+ consecutive identical bytes, suspicious (likely data table)
  if (max_same_opcode >= 4) {
    return true;
  }

  // Check for null-terminated string pattern
  // Look for sequences of printable chars followed by 0x00
  int null_terminated_strings = 0;
  for (uint32_t addr = start_address; addr < end_address; ++addr) {
    const uint8_t* byte = binary_->GetPointer(addr);
    if (!byte || *byte != 0x00) continue;

    // Found a null byte - check if preceded by printable chars
    int printable_before = 0;
    for (int i = 1; i <= 10 && addr >= start_address + i; ++i) {
      const uint8_t* prev = binary_->GetPointer(addr - i);
      if (!prev) break;
      uint8_t low = (*prev) & 0x7F;
      if (low >= 0x20 && low < 0x7F) {
        printable_before++;
      } else {
        break;
      }
    }

    if (printable_before >= 3) {
      null_terminated_strings++;
    }
  }

  // If we have null-terminated strings, likely data
  if (null_terminated_strings >= 1) {
    return true;
  }

  // Check for common data patterns (tables of addresses, etc.)
  // Look for patterns like: low byte, high byte pairs that look like addresses
  uint32_t address_like_pairs = 0;
  for (uint32_t addr = start_address; addr < end_address - 1; addr += 2) {
    const uint8_t* lo = binary_->GetPointer(addr);
    const uint8_t* hi = binary_->GetPointer(addr + 1);
    if (!lo || !hi) continue;

    // Check if this forms a reasonable address (typically $0000-$FFFF)
    // Common ranges: $0000-$00FF (zero page), $0800-$BFFF (user), $C000-$FFFF (ROM)
    uint16_t potential_addr = (*lo) | ((*hi) << 8);
    if (potential_addr >= 0x0800 || potential_addr < 0x0100) {
      address_like_pairs++;
    }
  }

  // If most pairs look like addresses, might be a jump table
  if (region_size >= 8 && address_like_pairs >= (region_size / 4)) {
    return true;
  }

  // Default: assume it's code
  return false;
}

float DataHeuristicsEngine::CalculatePrintablePercentage(uint32_t start,
                                                         uint32_t end) const {
  if (end <= start) return 0.0f;

  int printable_count = 0;
  int total_count = 0;

  for (uint32_t addr = start; addr <= end; ++addr) {
    const uint8_t* byte = binary_->GetPointer(addr);
    if (!byte) break;

    total_count++;
    uint8_t low = (*byte) & 0x7F;  // Strip high bit
    if (low >= 0x20 && low < 0x7F) {
      printable_count++;
    }
  }

  if (total_count == 0) return 0.0f;
  return static_cast<float>(printable_count) / static_cast<float>(total_count);
}

bool DataHeuristicsEngine::HasLongPrintableSequence(uint32_t start,
                                                    uint32_t end) const {
  int max_consecutive = 0;
  int current_consecutive = 0;

  for (uint32_t addr = start; addr <= end; ++addr) {
    const uint8_t* byte = binary_->GetPointer(addr);
    if (!byte) break;

    uint8_t low = (*byte) & 0x7F;
    if (low >= 0x20 && low < 0x7F) {
      current_consecutive++;
      max_consecutive = std::max(max_consecutive, current_consecutive);
    } else {
      current_consecutive = 0;
    }
  }

  return max_consecutive >= 24;  // Raised threshold
}

bool DataHeuristicsEngine::HasNullTerminatedStrings(uint32_t start,
                                                    uint32_t end) const {
  int null_terminated_strings = 0;

  for (uint32_t addr = start; addr < end; ++addr) {
    const uint8_t* byte = binary_->GetPointer(addr);
    if (!byte || *byte != 0x00) continue;

    // Check if preceded by printable chars
    int printable_before = 0;
    for (int i = 1; i <= 10 && addr >= start + i; ++i) {
      const uint8_t* prev = binary_->GetPointer(addr - i);
      if (!prev) break;
      uint8_t low = (*prev) & 0x7F;
      if (low >= 0x20 && low < 0x7F) {
        printable_before++;
      } else {
        break;
      }
    }

    if (printable_before >= 3) {
      null_terminated_strings++;
    }
  }

  return null_terminated_strings >= 1;
}

bool DataHeuristicsEngine::HasRepeatedBytes(uint32_t start, uint32_t end) const {
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

  return max_same >= 4;
}

bool DataHeuristicsEngine::HasAddressLikePairs(uint32_t start, uint32_t end) const {
  uint32_t region_size = end - start + 1;
  if (region_size < 8) return false;

  uint32_t address_like_pairs = 0;
  for (uint32_t addr = start; addr < end - 1; addr += 2) {
    const uint8_t* lo = binary_->GetPointer(addr);
    const uint8_t* hi = binary_->GetPointer(addr + 1);
    if (!lo || !hi) continue;

    uint16_t potential_addr = (*lo) | ((*hi) << 8);
    if (potential_addr >= 0x0800 || potential_addr < 0x0100) {
      address_like_pairs++;
    }
  }

  return address_like_pairs >= (region_size / 4);
}

bool DataHeuristicsEngine::HasRepeatedInstructions(uint32_t start,
                                                    uint32_t end) const {
  // Detect repeated identical instruction patterns (like graphics data)
  // Look for 8+ consecutive identical 2-byte instruction sequences
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

  return max_repeat >= 8;  // 8+ identical 2-byte patterns = graphics data
}

bool DataHeuristicsEngine::HasHighIllegalDensity(uint32_t start,
                                                  uint32_t end) const {
  // Note: This method requires cpu_ which we don't have in this engine
  // This will be handled by CodeAnalyzer directly for now
  // TODO: Consider passing CpuPlugin to constructor if needed
  return false;
}

int DataHeuristicsEngine::CountDataHeuristics(uint32_t start, uint32_t end) const {
  int count = 0;

  // Heuristic 1: High printable percentage (>90%)
  float printable_pct = CalculatePrintablePercentage(start, end);
  if (printable_pct > PRINTABLE_THRESHOLD_HIGH) {
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

  // Note: Heuristic 7 (HasHighIllegalDensity) requires CPU plugin
  // This will be handled by CodeAnalyzer directly

  return count;
}

int DataHeuristicsEngine::CountXrefsInRange(core::AddressMap* address_map,
                                            uint32_t start, uint32_t end) const {
  int count = 0;
  for (uint32_t addr = start; addr < end; ++addr) {
    if (address_map->HasXrefs(addr)) {
      count += address_map->GetXrefs(addr).size();
    }
  }
  return count;
}

}  // namespace analysis
}  // namespace sourcerer
