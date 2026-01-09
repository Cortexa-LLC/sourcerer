// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "analysis/code_analyzer.h"

#include <algorithm>
#include <cmath>
#include <sstream>
#include <iomanip>

#include "analysis/execution_simulator.h"
#include "utils/logger.h"

namespace sourcerer {
namespace analysis {

CodeAnalyzer::CodeAnalyzer(cpu::CpuPlugin* cpu, const core::Binary* binary)
    : cpu_(cpu),
      binary_(binary),
      data_heuristics_(std::make_unique<DataHeuristicsEngine>(binary)),
      graphics_detection_(std::make_unique<GraphicsDetectionStrategy>(binary)),
      misalignment_resolver_(std::make_unique<MisalignmentResolver>(cpu, binary)),
      entry_point_discovery_(std::make_unique<EntryPointDiscoveryStrategy>(cpu, binary)) {
  // Register known platform-specific inline data routines
  // ProDOS MLI: JSR $BF00 followed by 1 byte (command) + 2 bytes (param pointer)
  known_inline_data_routines_[0xBF00] = 3;

  // Share instruction cache with misalignment resolver (WP-01 Phase 3)
  misalignment_resolver_->SetInstructionCache(&instruction_cache_);
}

void CodeAnalyzer::AddEntryPoint(uint32_t address) {
  if (IsValidAddress(address)) {
    entry_points_.insert(address);
    LOG_DEBUG("Added entry point: $" + std::to_string(address));
  } else {
    LOG_WARNING("Invalid entry point address: $" + std::to_string(address));
  }
}

void CodeAnalyzer::Analyze(core::AddressMap* address_map) {
  if (!cpu_ || !binary_ || !address_map) {
    LOG_ERROR("CodeAnalyzer: Invalid parameters");
    return;
  }

  // Reset statistics
  instruction_count_ = 0;
  code_bytes_ = 0;
  data_bytes_ = 0;

  // If no entry points specified, use load address
  if (entry_points_.empty()) {
    AddEntryPoint(binary_->load_address());
  }

  // Add entry points to address map
  for (uint32_t ep : entry_points_) {
    address_map->AddEntryPoint(ep);
  }

  LOG_INFO("Starting code flow analysis from " +
           std::to_string(entry_points_.size()) + " entry point(s)");

  // Use NEW recursive traversal instead of queue-based
  RecursiveAnalyze(address_map);

  // Mark remaining bytes as data
  uint32_t start = binary_->load_address();
  uint32_t end = start + binary_->size();

  data_bytes_ = 0;
  for (uint32_t addr = start; addr < end; ++addr) {
    if (address_map->GetType(addr) == core::AddressType::UNKNOWN) {
      address_map->SetType(addr, core::AddressType::DATA);
      data_bytes_++;
    }
  }

  // Update code_bytes from recursive analysis
  code_bytes_ = code_bytes_discovered_;

  LOG_INFO("Code flow analysis complete");
  LOG_INFO("  Instructions: " + std::to_string(instruction_count_));
  LOG_INFO("  Code bytes: " + std::to_string(code_bytes_));
  LOG_INFO("  Data bytes: " + std::to_string(data_bytes_));

  // Count UNKNOWN bytes
  uint32_t unknown_bytes = 0;
  for (uint32_t addr = binary_->load_address();
       addr < binary_->load_address() + binary_->size(); ++addr) {
    if (address_map->GetType(addr) == core::AddressType::UNKNOWN) {
      unknown_bytes++;
    }
  }
  LOG_INFO("  Unknown bytes: " + std::to_string(unknown_bytes));

  // Second pass: Reclassify CODE after computed jumps
  LOG_INFO("Running second pass: computed jump cleanup...");
  ReclassifyAfterComputedJumps(address_map);
  LOG_INFO("Computed jump cleanup complete");

  // Third pass: Reclassify CODE regions that look like data
  LOG_INFO("Running third pass: data region detection...");
  ReclassifyDataRegions(address_map);
  LOG_INFO("Third pass complete");
}

bool CodeAnalyzer::IsValidAddress(uint32_t address) const {
  uint32_t start = binary_->load_address();
  uint32_t end = start + binary_->size();
  return address >= start && address < end;
}

uint32_t CodeAnalyzer::FindFirstValidInstruction(uint32_t start_address) const {
  // Check for common ROM headers and skip them
  const uint8_t* data = binary_->GetPointer(start_address);
  if (data && binary_->size() >= 2) {
    // CoCo "EX" Extended BASIC header
    if (data[0] == 0x45 && data[1] == 0x58) {
      LOG_INFO("Detected CoCo Extended BASIC ROM header (EX), skipping 2 bytes");
      return start_address + 2;
    }
  }

  // Try to find first valid instruction within first 16 bytes
  // This handles other ROM headers and non-code prefixes
  const uint32_t MAX_SCAN = 16;
  const uint32_t MIN_SEQUENCE = 3;  // Require 3 consecutive valid instructions

  struct Candidate {
    uint32_t address;
    uint32_t score;
  };

  std::vector<Candidate> candidates;

  for (uint32_t offset = 0; offset < MAX_SCAN; ++offset) {
    uint32_t addr = start_address + offset;

    if (!IsValidAddress(addr)) {
      break;
    }

    // Try to disassemble a sequence of instructions from this address
    uint32_t current = addr;
    uint32_t valid_count = 0;
    uint32_t score = 0;
    bool sequence_valid = true;

    for (uint32_t i = 0; i < MIN_SEQUENCE && sequence_valid; ++i) {
      if (!IsValidAddress(current)) {
        sequence_valid = false;
        break;
      }

      const uint8_t* data = binary_->GetPointer(current);
      size_t remaining = binary_->size() - (current - binary_->load_address());

      if (!data || remaining == 0) {
        sequence_valid = false;
        break;
      }

      try {
        core::Instruction inst = cpu_->Disassemble(data, remaining, current);

        // Check if instruction is valid
        if (inst.bytes.empty() || inst.is_illegal || inst.mnemonic == "???") {
          sequence_valid = false;
          break;
        }

        // Score instructions - prefer typical entry point patterns
        if (i == 0) {
          // First instruction scoring (higher score = more likely entry point)
          if (inst.bytes.size() >= 2) {
            score += 10;  // Multi-byte instructions more likely than single-byte
          }
          // Common entry point instructions for 6809/6502
          if (inst.mnemonic == "LDX" || inst.mnemonic == "LDY" ||
              inst.mnemonic == "LDS" || inst.mnemonic == "LDU" ||
              inst.mnemonic == "SEI" || inst.mnemonic == "CLD" ||
              inst.mnemonic == "JMP" || inst.mnemonic == "JSR") {
            score += 20;
          }
        }

        valid_count++;
        current += inst.bytes.size();
      } catch (const std::out_of_range&) {
        // Address out of bounds
        sequence_valid = false;
        break;
      } catch (const std::runtime_error&) {
        // Invalid opcode - not a valid code sequence
        sequence_valid = false;
        break;
      }
    }

    // If we found a valid sequence, add as candidate
    if (sequence_valid && valid_count >= MIN_SEQUENCE) {
      candidates.push_back({addr, score});
    }
  }

  // Return the best candidate (highest score, prefer earlier address if tied)
  if (!candidates.empty()) {
    auto best = std::max_element(candidates.begin(), candidates.end(),
      [](const Candidate& a, const Candidate& b) {
        if (a.score != b.score) {
          return a.score < b.score;  // Higher score is better
        }
        return a.address > b.address;  // Lower address is better (prefer earlier)
      });

    uint32_t best_addr = best->address;
    uint32_t offset = best_addr - start_address;

    if (offset > 0) {
      LOG_INFO("Skipped " + std::to_string(offset) +
               " byte(s) of non-code data at start of binary");
    }

    LOG_INFO("FindFirstValidInstruction: start=$" + std::to_string(start_address) +
              " best=$" + std::to_string(best_addr) + " score=" + std::to_string(best->score));

    return best_addr;
  }

  // No valid sequence found, return original address
  LOG_WARNING("No valid instruction sequence found in first " + std::to_string(MAX_SCAN) +
              " bytes, using original entry point");
  return start_address;
}


void CodeAnalyzer::ReclassifyAfterComputedJumps(core::AddressMap* address_map) {
  // Scan all CODE regions for computed jumps (JMP with indexed addressing)
  // and reclassify unreachable bytes after them as DATA
  uint32_t start = binary_->load_address();
  uint32_t end = start + binary_->size();

  for (uint32_t addr = start; addr < end; ) {
    // Skip non-CODE regions
    if (!address_map->IsCode(addr)) {
      addr++;
      continue;
    }

    // Try to disassemble instruction at this address
    const uint8_t* data = binary_->GetPointer(addr);
    size_t remaining = end - addr;
    if (!data || remaining == 0) {
      addr++;
      continue;
    }

    core::Instruction inst;
    try {
      inst = cpu_->Disassemble(data, remaining, addr);
    } catch (const std::out_of_range&) {
      // Address out of bounds - skip to next
      addr++;
      continue;
    } catch (const std::runtime_error&) {
      // Invalid opcode - skip to next
      addr++;
      continue;
    }

    // Check if this is a computed jump
    if (inst.is_jump && !inst.is_branch &&
        inst.mode == core::AddressingMode::INDEXED) {
      // Found computed jump - mark unreachable bytes after it as DATA
      uint32_t after_jump = addr + inst.bytes.size();
      const size_t MAX_DATA_SCAN = 64;

      LOG_DEBUG("Found computed jump at $" + std::to_string(addr) +
               ", scanning for unreachable bytes");

      // Track which addresses we've reclassified in THIS scan
      // so we don't count xrefs from already-reclassified unreachable code
      std::set<uint32_t> reclassified_addrs;

      int reclassified = 0;
      for (size_t i = 0; i < MAX_DATA_SCAN && (after_jump + i) < end; ++i) {
        uint32_t data_addr = after_jump + i;

        // Check if this address has cross-references from REACHABLE code
        // (not from other unreachable code after this computed jump)
        const auto& xrefs = address_map->GetXrefs(data_addr);
        bool has_reachable_xref = false;
        for (uint32_t xref_source : xrefs) {
          // If the xref comes from before the computed jump, it's reachable
          if (xref_source < addr) {
            has_reachable_xref = true;
            break;
          }
          // If xref comes from after but outside our scan window, it's reachable
          if (xref_source >= (after_jump + MAX_DATA_SCAN)) {
            has_reachable_xref = true;
            break;
          }
          // CRITICAL: If xref comes from inside the scan window, it's likely
          // also unreachable. There are two cases:
          // 1. Source was already reclassified → definitely unreachable
          // 2. Source is ahead of current position → assume unreachable
          // 3. Source is behind current position and still CODE → might be reachable,
          //    but only if it's not going to be reclassified later
          if (xref_source >= after_jump && xref_source < (after_jump + MAX_DATA_SCAN)) {
            // If already reclassified, ignore this xref
            if (reclassified_addrs.find(xref_source) != reclassified_addrs.end()) {
              continue;  // Unreachable, skip this xref
            }
            // If source is ahead of us in the scan, assume it's also unreachable
            if (xref_source >= data_addr) {
              continue;  // Will be reclassified later, skip this xref
            }
            // Source is behind us and hasn't been reclassified yet
            // This means it was preserved for some reason, so count it as reachable
            if (address_map->IsCode(xref_source)) {
              has_reachable_xref = true;
              break;
            }
          }
        }

        if (has_reachable_xref) {
          LOG_DEBUG("  Stopped at $" + std::to_string(data_addr) +
                   " (has reachable xrefs)");
          break;
        }

        // Reclassify CODE as DATA (but preserve entry points and xref targets)
        if (address_map->IsCode(data_addr)) {
          // Don't reclassify if it's an entry point
          const auto& entry_points = address_map->GetEntryPoints();
          if (entry_points.find(data_addr) != entry_points.end()) {
            LOG_DEBUG("  Stopped at $" + std::to_string(data_addr) +
                     " (is entry point)");
            break;
          }

          address_map->SetType(data_addr, core::AddressType::DATA);
          reclassified_addrs.insert(data_addr);  // Track this for xref checking
          reclassified++;
        }
      }

      if (reclassified > 0) {
        LOG_INFO("Reclassified " + std::to_string(reclassified) +
                " unreachable bytes as DATA after computed jump at $" +
                std::to_string(addr));
      }
    }

    // Move to next instruction
    addr += std::max(size_t(1), inst.bytes.size());
  }
}

void CodeAnalyzer::ReclassifyMixedCodeDataRegions(core::AddressMap* address_map) {
  // Detect CODE regions that contain instruction gaps - these are mixed CODE/DATA
  // A gap is a byte marked as CODE but not covered by any disassembled instruction

  uint32_t start = binary_->load_address();
  uint32_t end = start + binary_->size();

  // CRITICAL: Rebuild instruction cache by re-disassembling all CODE regions
  // The cache may have been cleared during analysis passes
  instruction_cache_.clear();

  uint32_t addr = start;
  while (addr < end) {
    if (!address_map->IsCode(addr)) {
      addr++;
      continue;
    }

    // Try to disassemble instruction at this CODE address
    size_t offset = addr - binary_->load_address();
    const uint8_t* data = binary_->GetPointer(addr);
    size_t remaining = binary_->size() - offset;

    if (!data || remaining == 0) {
      addr++;
      continue;
    }

    try {
      core::Instruction inst = cpu_->Disassemble(data, remaining, addr);

      if (!inst.bytes.empty() && !inst.is_illegal) {
        // Valid instruction - add to cache
        instruction_cache_[addr] = inst;
        addr += inst.bytes.size();
      } else {
        // Invalid instruction at CODE address (potential phantom)
        addr++;
      }
    } catch (const std::out_of_range&) {
      // Address out of bounds at CODE address (potential phantom)
      addr++;
    } catch (const std::runtime_error&) {
      // Disassembly failed at CODE address (potential phantom)
      addr++;
    }
  }

  LOG_DEBUG("Rebuilt instruction cache: " +
            std::to_string(instruction_cache_.size()) + " instructions");

  // Build a map of which CODE bytes are actually part of instructions
  std::set<uint32_t> instruction_bytes;
  for (const auto& pair : instruction_cache_) {
    uint32_t inst_addr = pair.first;
    const core::Instruction& inst = pair.second;

    for (size_t i = 0; i < inst.bytes.size(); ++i) {
      instruction_bytes.insert(inst_addr + i);
    }
  }

  // Scan for CODE regions with gaps
  addr = start;
  while (addr < end) {
    // Find start of CODE region
    while (addr < end && !address_map->IsCode(addr)) {
      addr++;
    }
    if (addr >= end) break;

    // Find end of contiguous CODE region
    uint32_t code_start = addr;
    while (addr < end && address_map->IsCode(addr)) {
      addr++;
    }
    uint32_t code_end = addr;

    // Check if this CODE region has gaps (non-instruction bytes)
    int gap_bytes = 0;
    int total_bytes = code_end - code_start;

    for (uint32_t check_addr = code_start; check_addr < code_end; ++check_addr) {
      if (!instruction_bytes.count(check_addr)) {
        gap_bytes++;
      }
    }

    // If more than 50% of the CODE region is gaps, it's mixed CODE/DATA
    // This is very conservative - only catches severely broken regions
    float gap_percentage = static_cast<float>(gap_bytes) / total_bytes;

    if (gap_percentage > 0.50f && total_bytes >= 8) {
      // CRITICAL: Don't reclassify regions that contain xref targets
      // These are addresses that are referenced by branches/calls and must remain CODE
      bool has_xref_targets = false;
      for (uint32_t check_addr = code_start; check_addr < code_end; ++check_addr) {
        if (address_map->HasXrefs(check_addr)) {
          has_xref_targets = true;

          std::stringstream ss_skip;
          ss_skip << std::hex << std::uppercase;
          ss_skip << "Mixed CODE/DATA at $" << code_start << "-$" << code_end
                  << " has xref target at $" << check_addr << " - preserving as CODE";
          LOG_DEBUG(ss_skip.str());
          break;
        }
      }

      if (has_xref_targets) {
        // Skip reclassification - this region has valid code targets
        continue;
      }

      std::stringstream ss;
      ss << std::hex << std::uppercase;
      ss << "Mixed CODE/DATA detected at $" << code_start << "-$" << code_end;
      ss << " (" << gap_bytes << "/" << total_bytes << " bytes = "
         << static_cast<int>(gap_percentage * 100) << "% gaps)";
      LOG_INFO(ss.str());

      // Reclassify entire region as DATA
      for (uint32_t reclassify_addr = code_start; reclassify_addr < code_end; ++reclassify_addr) {
        address_map->SetType(reclassify_addr, core::AddressType::DATA);

        // Clear any xrefs originating from this address (phantom instructions)
        address_map->RemoveXrefsFrom(reclassify_addr);
      }

      // Clear visited markers to allow re-analysis if needed
      for (uint32_t clear_addr = code_start; clear_addr < code_end; ++clear_addr) {
        visited_recursive_.erase(clear_addr);
      }

      ss.str("");
      ss << "Reclassified $" << code_start << "-$" << code_end << " as DATA";
      LOG_INFO(ss.str());
    }
  }
}

void CodeAnalyzer::ReclassifyDataRegions(core::AddressMap* address_map) {
  // NEW: Conservative reclassification with mixed CODE/DATA detection
  // Find contiguous CODE regions and scan for suspicious sub-regions
  uint32_t start = binary_->load_address();
  uint32_t end = start + binary_->size();

  // DISABLED: Mixed CODE/DATA reclassification is too aggressive
  // It destroys valid CODE regions that happen to have JSR targets
  // The xrefs don't exist yet when this runs, so we can't protect xref targets
  // TODO: Re-enable with better heuristics or run after xref building
  // ReclassifyMixedCodeDataRegions(address_map);

  uint32_t addr = start;
  while (addr < end) {
    // Skip non-CODE bytes
    while (addr < end && !address_map->IsCode(addr)) {
      addr++;
    }
    if (addr >= end) break;

    // Found start of CODE region - find the end of this contiguous CODE block
    uint32_t code_block_start = addr;
    uint32_t code_block_end = addr;
    while (code_block_end < end && address_map->IsCode(code_block_end)) {
      code_block_end++;
    }

    // Check if this CODE block contains any explicit DATA markers
    bool contains_explicit_data = false;
    for (uint32_t check_addr = code_block_start; check_addr < code_block_end; ++check_addr) {
      core::AddressType type = address_map->GetType(check_addr);
      if (type == core::AddressType::DATA || type == core::AddressType::INLINE_DATA) {
        contains_explicit_data = true;
        break;
      }
    }

    // If this CODE block contains explicit DATA markers, skip it entirely
    if (contains_explicit_data) {
      LOG_DEBUG("Skipping CODE block $" + std::to_string(code_block_start) +
                "-$" + std::to_string(code_block_end - 1) +
                " (contains explicit DATA markers)");
      addr = code_block_end;
      continue;
    }

    // Use a sliding window approach (increased window size)
    const uint32_t window_size = MIN_DATA_REGION_SIZE;

    addr = code_block_start;
    while (addr < code_block_end) {
      uint32_t window_end = std::min(addr + window_size, code_block_end);

      // For regions at least MIN_DATA_REGION_SIZE bytes
      if (window_end - addr >= window_size) {
        // Count how many heuristics match
        int heuristic_matches = CountDataHeuristics(addr, window_end - 1);

        // Check cross-references
        int xref_count = CountXrefsInRange(address_map, addr, window_end);

        // Only reclassify if:
        // 1. At least MIN_HEURISTIC_MATCHES heuristics match
        // 2. No incoming cross-references
        // 3. Region is at least MIN_DATA_REGION_SIZE bytes
        // 4. No entry points in region
        if (heuristic_matches >= MIN_HEURISTIC_MATCHES && xref_count == 0) {
          // Extend region
          uint32_t data_end = window_end;
          while (data_end < code_block_end && address_map->IsCode(data_end)) {
            int extended_matches = CountDataHeuristics(addr, data_end);
            if (extended_matches < MIN_HEURISTIC_MATCHES) break;
            data_end++;
          }

          // CRITICAL: Re-check for xrefs in the EXTENDED range
          // The initial window might not have xrefs, but the extended region might
          int extended_xref_count = CountXrefsInRange(address_map, addr, data_end);
          if (extended_xref_count > 0) {
            LOG_DEBUG("Skipping region $" + std::to_string(addr) +
                     "-$" + std::to_string(data_end - 1) +
                     " (extended region has " + std::to_string(extended_xref_count) + " xrefs)");
            // Skip past this entire region, not just 1 byte
            addr = data_end;
            continue;
          }

          // Check for entry points
          bool contains_entry_point = false;
          for (uint32_t ep : entry_points_) {
            if (ep >= addr && ep < data_end) {
              contains_entry_point = true;
              break;
            }
          }

          if (!contains_entry_point && (data_end - addr) >= MIN_DATA_REGION_SIZE) {
            LOG_DEBUG("Reclassifying CODE region $" + std::to_string(addr) +
                      "-$" + std::to_string(data_end - 1) + " as DATA (" +
                      std::to_string(heuristic_matches) + " heuristics matched)");

            // Reclassify this region as DATA
            for (uint32_t a = addr; a < data_end; ++a) {
              address_map->SetType(a, core::AddressType::DATA);
            }

            addr = data_end;
            continue;
          }
        }
      }

      addr++;
    }
  }
}

bool CodeAnalyzer::LooksLikeData(uint32_t start_address, uint32_t end_address) const {
  // Delegate to DataHeuristicsEngine (WP-01 Phase 1)
  return data_heuristics_->LooksLikeData(start_address, end_address);
}

float CodeAnalyzer::CalculatePrintablePercentage(uint32_t start, uint32_t end) const {
  // Delegate to DataHeuristicsEngine (WP-01 Phase 1)
  return data_heuristics_->CalculatePrintablePercentage(start, end);
}

// NEW: Conservative reclassification helper methods
int CodeAnalyzer::CountXrefsInRange(core::AddressMap* address_map,
                                    uint32_t start, uint32_t end) const {
  // Delegate to DataHeuristicsEngine (WP-01 Phase 1)
  return data_heuristics_->CountXrefsInRange(address_map, start, end);
}

bool CodeAnalyzer::HasLongPrintableSequence(uint32_t start, uint32_t end) const {
  // Delegate to DataHeuristicsEngine (WP-01 Phase 1)
  return data_heuristics_->HasLongPrintableSequence(start, end);
}

bool CodeAnalyzer::HasNullTerminatedStrings(uint32_t start, uint32_t end) const {
  // Delegate to DataHeuristicsEngine (WP-01 Phase 1)
  return data_heuristics_->HasNullTerminatedStrings(start, end);
}

bool CodeAnalyzer::HasRepeatedBytes(uint32_t start, uint32_t end) const {
  // Delegate to DataHeuristicsEngine (WP-01 Phase 1)
  return data_heuristics_->HasRepeatedBytes(start, end);
}

bool CodeAnalyzer::HasAddressLikePairs(uint32_t start, uint32_t end) const {
  // Delegate to DataHeuristicsEngine (WP-01 Phase 1)
  return data_heuristics_->HasAddressLikePairs(start, end);
}

bool CodeAnalyzer::HasRepeatedInstructions(uint32_t start, uint32_t end) const {
  // Delegate to DataHeuristicsEngine (WP-01 Phase 1)
  return data_heuristics_->HasRepeatedInstructions(start, end);
}

bool CodeAnalyzer::HasHighIllegalDensity(uint32_t start, uint32_t end) const {
  // Check if region has many illegal opcodes (suggests data, not code)
  int illegal_count = 0;
  int total_bytes = 0;

  for (uint32_t addr = start; addr < end && total_bytes < 32; ) {
    const uint8_t* data = binary_->GetPointer(addr);
    if (!data) break;

    size_t remaining = end - addr;
    try {
      core::Instruction inst = cpu_->Disassemble(data, remaining, addr);
      if (inst.is_illegal) {
        illegal_count++;
      }
      addr += std::max(size_t(1), inst.bytes.size());
      total_bytes += std::max(size_t(1), inst.bytes.size());
    } catch (const std::out_of_range&) {
      // Address out of bounds - count as illegal
      illegal_count++;
      addr++;
      total_bytes++;
    } catch (const std::runtime_error&) {
      // Invalid opcode - count as illegal
      illegal_count++;
      addr++;
      total_bytes++;
    }
  }

  if (total_bytes == 0) return false;

  float illegal_ratio = static_cast<float>(illegal_count) /
                        static_cast<float>(total_bytes);
  return illegal_ratio > 0.3f;  // >30% illegal = likely data
}

// Graphics data detection heuristics

float CodeAnalyzer::CalculateEntropy(const uint8_t* data, size_t length) const {
  // Delegate to GraphicsDetectionStrategy (WP-01 Phase 2)
  return graphics_detection_->CalculateEntropy(data, length);
}

bool CodeAnalyzer::HasBitmapEntropy(uint32_t start, uint32_t end) const {
  // Delegate to GraphicsDetectionStrategy (WP-01 Phase 2)
  return graphics_detection_->HasBitmapEntropy(start, end);
}

bool CodeAnalyzer::HasByteAlignment(uint32_t start, uint32_t end) const {
  // Delegate to GraphicsDetectionStrategy (WP-01 Phase 2)
  return graphics_detection_->HasByteAlignment(start, end);
}

bool CodeAnalyzer::IsInGraphicsRegion(uint32_t start, uint32_t end) const {
  // Delegate to GraphicsDetectionStrategy (WP-01 Phase 2)
  return graphics_detection_->IsInGraphicsRegion(start, end);
}

bool CodeAnalyzer::HasSpritePatterns(uint32_t start, uint32_t end) const {
  // Delegate to GraphicsDetectionStrategy (WP-01 Phase 2)
  return graphics_detection_->HasSpritePatterns(start, end);
}

int CodeAnalyzer::CountDataHeuristics(uint32_t start, uint32_t end) const {
  // Delegate data heuristics to DataHeuristicsEngine (WP-01 Phase 1)
  int count = data_heuristics_->CountDataHeuristics(start, end);

  // Add CPU-specific heuristic that requires cpu_ plugin
  if (HasHighIllegalDensity(start, end)) {
    count++;
  }

  // Add graphics heuristics (will be moved to GraphicsDetectionStrategy in Phase 2)
  if (HasBitmapEntropy(start, end)) {
    count++;
  }
  if (HasByteAlignment(start, end)) {
    count++;
  }
  if (IsInGraphicsRegion(start, end)) {
    count++;
  }
  if (HasSpritePatterns(start, end)) {
    count++;
  }

  return count;
}

// NEW: Recursive traversal implementation
void CodeAnalyzer::AnalyzeRecursively(uint32_t address,
                                     core::AddressMap* address_map,
                                     int depth) {
  // Prevent infinite recursion
  if (depth > MAX_RECURSION_DEPTH) {
    LOG_WARNING("Max recursion depth reached at $" + std::to_string(address));
    return;
  }

  // Skip if already visited in this recursive pass
  if (visited_recursive_.count(address)) {
    return;
  }

  // Skip if outside binary bounds
  if (!IsValidAddress(address)) {
    return;
  }

  // Skip if already confirmed as DATA
  if (address_map->GetType(address) == core::AddressType::DATA) {
    return;
  }

  visited_recursive_.insert(address);

  uint32_t current = address;

  while (true) {
    // Check if we've already processed this address
    if (address_map->IsCode(current) && current != address) {
      // Reached already-analyzed code, can stop this path
      break;
    }

    // Try to disassemble instruction
    size_t offset = current - binary_->load_address();
    const uint8_t* data = binary_->GetPointer(current);
    size_t remaining = binary_->size() - offset;

    if (!data || remaining == 0) break;

    core::Instruction inst;
    try {
      inst = cpu_->Disassemble(data, remaining, current);
    } catch (const std::out_of_range&) {
      // Address out of bounds - mark as DATA and stop this path
      address_map->SetType(current, core::AddressType::DATA);
      break;
    } catch (const std::runtime_error&) {
      // Invalid opcode - mark as DATA and stop this path
      address_map->SetType(current, core::AddressType::DATA);
      break;
    }

    if (inst.bytes.empty() || inst.is_illegal) {
      // Mark illegal opcodes as DATA, not CODE
      address_map->SetType(current, core::AddressType::DATA);
      break;  // Can't continue on this path
    }

    // Mark instruction bytes as CODE and cache the instruction
    bool is_new_instruction = !address_map->IsCode(current);
    for (size_t i = 0; i < inst.bytes.size(); ++i) {
      if (!address_map->IsCode(current + i)) {
        address_map->SetType(current + i, core::AddressType::CODE);
        code_bytes_discovered_++;
      }
    }

    // Cache instruction at this boundary
    instruction_cache_[current] = inst;

    // Count instruction if it's new
    if (is_new_instruction) {
      instruction_count_++;
    }

    // Track LEA/LEAX/LEAY targets (potential data pointers)
    if (inst.mnemonic == "LEAX" || inst.mnemonic == "LEAY" ||
        inst.mnemonic == "LEAU" || inst.mnemonic == "LEAS") {
      if (inst.target_address != 0) {
        lea_targets_.insert(inst.target_address);
      }
    }

    // Handle branches - RECURSIVELY explore both paths
    if (inst.is_branch) {
      if (inst.target_address != 0) {
        // Add cross-reference
        address_map->AddXref(inst.target_address, current);

        // Check for misalignment
        bool should_follow = true;
        if (DetectMisalignment(inst.target_address, address_map)) {
          // Check if this is an unconditional branch (BRA, LBRA)
          bool is_unconditional = (inst.mnemonic == "BRA" || inst.mnemonic == "LBRA");

          // Resolve the conflict
          should_follow = ResolveMisalignment(inst.target_address, current,
                                             is_unconditional, address_map);
        }

        // RECURSIVE: Follow branch target if resolved or no conflict
        if (should_follow) {
          AnalyzeRecursively(inst.target_address, address_map, depth + 1);
        }
      }

      // CRITICAL: Continue to next instruction (branch not taken path)
      current += inst.bytes.size();
      continue;
    }

    // Handle jumps - explore target then STOP this path
    if (inst.is_jump) {
      if (inst.target_address != 0) {
        address_map->AddXref(inst.target_address, current);

        // Check for misalignment
        bool should_follow = true;
        if (DetectMisalignment(inst.target_address, address_map)) {
          // Jumps are unconditional
          should_follow = ResolveMisalignment(inst.target_address, current,
                                             true, address_map);
        }

        // RECURSIVE: Follow jump target if resolved or no conflict
        if (should_follow) {
          AnalyzeRecursively(inst.target_address, address_map, depth + 1);
        }
      }

      // Jump terminates this path
      break;
    }

    // Handle calls - follow target AND continue
    if (inst.is_call) {
      if (inst.target_address != 0) {
        address_map->AddXref(inst.target_address, current);

        // Check for misalignment
        bool should_follow = true;
        if (DetectMisalignment(inst.target_address, address_map)) {
          // JSR is unconditional
          should_follow = ResolveMisalignment(inst.target_address, current,
                                             true, address_map);
        }

        // RECURSIVE: Analyze subroutine if resolved or no conflict
        if (should_follow) {
          AnalyzeRecursively(inst.target_address, address_map, depth + 1);
        }
      }

      // Continue after call
      current += inst.bytes.size();
      continue;
    }

    // Handle returns - stop path
    if (inst.is_return) {
      break;
    }

    // Normal instruction - continue to next
    current += inst.bytes.size();
  }
}

int CodeAnalyzer::RunAnalysisPass(core::AddressMap* address_map) {
  int initial_bytes = code_bytes_discovered_;

  // Clear visited set for new pass (but keep instruction cache for post-pass detection)
  visited_recursive_.clear();

  // Analyze from all known entry points
  for (uint32_t ep : entry_points_) {
    AnalyzeRecursively(ep, address_map, 0);
  }

  // Also analyze from newly discovered entry points
  for (uint32_t ep : discovered_entry_points_) {
    AnalyzeRecursively(ep, address_map, 0);
  }

  int bytes_this_pass = code_bytes_discovered_ - initial_bytes;
  LOG_INFO("Pass " + std::to_string(passes_completed_) +
           " discovered " + std::to_string(bytes_this_pass) + " bytes");

  // Post-pass: detect and resolve misalignments (needs instruction_cache_)
  LOG_DEBUG("Running post-pass misalignment detection...");
  bool resolved_misalignments = DetectAndResolvePostPassMisalignments(address_map);

  // NOW clear instruction cache for next pass
  instruction_cache_.clear();

  if (resolved_misalignments) {
    LOG_INFO("Post-pass resolved conflicts, forcing re-analysis");
    // Return non-zero to force another pass
    return 1;
  }

  return bytes_this_pass;
}

void CodeAnalyzer::RecursiveAnalyze(core::AddressMap* address_map) {
  LOG_INFO("Starting recursive code flow analysis...");

  code_bytes_discovered_ = 0;
  passes_completed_ = 0;

  // Run multiple passes until no new code discovered
  const int MAX_PASSES = 10;

  for (int pass = 0; pass < MAX_PASSES; ++pass) {
    passes_completed_++;

    int bytes_discovered = RunAnalysisPass(address_map);

    if (bytes_discovered == 0) {
      LOG_INFO("Recursive analysis converged after " +
               std::to_string(passes_completed_) + " pass(es)");
      break;
    }

    // After each pass, run discovery heuristics to find new entry points
    if (pass < MAX_PASSES - 1) {
      DiscoverEntryPoints(address_map);
      ScanForJumpTables(address_map);
    }
  }

  LOG_INFO("Recursive analysis complete:");
  LOG_INFO("  Total code bytes: " + std::to_string(code_bytes_discovered_));
  LOG_INFO("  Passes: " + std::to_string(passes_completed_));

  // Run dynamic analysis to discover remaining branch targets
  LOG_INFO("Starting dynamic analysis phase...");
  DynamicAnalysis(address_map);

  // If dynamic analysis found new entry points, run one more pass
  if (!discovered_entry_points_.empty()) {
    size_t new_entries = discovered_entry_points_.size();
    LOG_INFO("Dynamic analysis discovered " + std::to_string(new_entries) +
             " new entry point(s), running final pass...");
    passes_completed_++;
    int bytes_discovered = RunAnalysisPass(address_map);
    LOG_INFO("Final pass discovered " + std::to_string(bytes_discovered) + " bytes");
  }
}

// Phase 3: Entry Point Discovery Implementation
bool CodeAnalyzer::IsLikelyCode(uint32_t address, size_t scan_length) const {
  // Delegate to EntryPointDiscoveryStrategy (WP-01 Phase 4)
  return entry_point_discovery_->IsLikelyCode(address, scan_length);
}

bool CodeAnalyzer::LooksLikeSubroutineStart(uint32_t address) const {
  // Delegate to EntryPointDiscoveryStrategy (WP-01 Phase 4)
  return entry_point_discovery_->LooksLikeSubroutineStart(address);
}

void CodeAnalyzer::ScanInterruptVectors() {
  // Delegate to EntryPointDiscoveryStrategy (WP-01 Phase 4)
  entry_point_discovery_->ScanInterruptVectors(&discovered_entry_points_);
}

void CodeAnalyzer::ScanForSubroutinePatterns(core::AddressMap* address_map) {
  // Delegate to EntryPointDiscoveryStrategy (WP-01 Phase 4)
  entry_point_discovery_->ScanForSubroutinePatterns(
      address_map, &discovered_entry_points_, &lea_targets_);
}

// CoCo-specific entry point detection

bool CodeAnalyzer::IsCoCoCartridgeSpace(uint32_t address) const {
  // Delegate to EntryPointDiscoveryStrategy (WP-01 Phase 4)
  return entry_point_discovery_->IsCoCoCartridgeSpace(address);
}

bool CodeAnalyzer::HasCoCoPreamble(uint32_t address) const {
  // Delegate to EntryPointDiscoveryStrategy (WP-01 Phase 4)
  return entry_point_discovery_->HasCoCoPreamble(address);
}

void CodeAnalyzer::ScanCoCoCartridgeEntryPoints() {
  // Delegate to EntryPointDiscoveryStrategy (WP-01 Phase 4)
  entry_point_discovery_->ScanCoCoCartridgeEntryPoints(&discovered_entry_points_);
}

void CodeAnalyzer::ScanCoCoStandardEntryPoints() {
  // Delegate to EntryPointDiscoveryStrategy (WP-01 Phase 4)
  entry_point_discovery_->ScanCoCoStandardEntryPoints(&discovered_entry_points_);
}

void CodeAnalyzer::DiscoverEntryPoints(core::AddressMap* address_map) {
  // Delegate to EntryPointDiscoveryStrategy (WP-01 Phase 4)
  entry_point_discovery_->DiscoverEntryPoints(
      address_map, &discovered_entry_points_, &lea_targets_);
}

// Phase 4: Jump Table Detection Implementation

bool CodeAnalyzer::IsLikelyCodePointer(uint16_t address) const {
  // Check if address is in typical code region
  // For cartridges, use the load address as minimum
  // For disk programs, use conservative minimums: 6809: $4000, 6502: $0800
  uint32_t load_addr = binary_->load_address();
  uint32_t binary_end = load_addr + binary_->size();
  uint32_t min_code_addr;
  uint32_t max_code_addr;

  if (load_addr >= 0x8000) {
    // Cartridge ROM - use load address as minimum
    min_code_addr = load_addr;
    // Maximum: either end of binary OR system ROM (allow jumps to BIOS)
    // CoCo system ROM: $C000-$FFFF
    max_code_addr = 0xFFFF;
  } else {
    // Disk/tape program - use conservative minimum
    min_code_addr = (cpu_->GetVariant() == cpu::CpuVariant::MOTOROLA_6809) ? 0x4000 : 0x0800;
    max_code_addr = 0xFFFF;
  }

  // Address must be within valid range
  if (address < min_code_addr || address > max_code_addr) return false;

  // Address must be either:
  // 1. Within the binary bounds, OR
  // 2. In system ROM (>= $C000 for CoCo)
  bool in_binary = (address >= load_addr && address < binary_end);
  bool in_system_rom = (address >= 0xC000);  // CoCo system ROM

  return in_binary || in_system_rom;
}

std::vector<CodeAnalyzer::JumpTableCandidate>
CodeAnalyzer::FindJumpTableCandidates(core::AddressMap* address_map) const {
  std::vector<JumpTableCandidate> candidates;

  uint32_t start = binary_->load_address();
  uint32_t end = start + binary_->size();

  // Scan DATA and UNKNOWN regions only (skip CODE regions)
  for (uint32_t addr = start; addr < end - 1; ++addr) {
    // Skip CODE regions - we already analyzed them
    if (address_map->IsCode(addr)) {
      continue;
    }

    std::vector<uint32_t> targets;
    uint32_t table_start = addr;
    uint32_t current = addr;

    // Try to read consecutive 16-bit values
    while (current < end - 1 && targets.size() < MAX_JUMP_TABLE_ENTRIES) {
      const uint8_t* data = binary_->GetPointer(current);
      if (!data) break;

      // Read 16-bit value considering CPU endianness
      uint16_t value;
      if (cpu_->GetVariant() == cpu::CpuVariant::MOTOROLA_6809) {
        // Big-endian
        value = (static_cast<uint16_t>(data[0]) << 8) | data[1];
      } else {
        // Little-endian (6502)
        value = data[0] | (static_cast<uint16_t>(data[1]) << 8);
      }

      // Check if this looks like a code pointer
      if (IsLikelyCodePointer(value)) {
        targets.push_back(value);
        current += 2;
      } else {
        break;  // Stop at first non-pointer
      }
    }

    // If we found enough consecutive entries, it's a candidate
    if (targets.size() >= MIN_JUMP_TABLE_ENTRIES) {
      JumpTableCandidate candidate;
      candidate.start_address = table_start;
      candidate.end_address = current - 1;
      candidate.targets = targets;
      candidate.confidence = 0.0f;  // Will be calculated next

      candidates.push_back(candidate);

      // Skip past this table to avoid overlapping candidates
      addr = current - 1;
    }
  }

  return candidates;
}

float CodeAnalyzer::CalculateTableConfidence(
    const JumpTableCandidate& candidate) const {
  float confidence = 0.0f;

  // Factor 1: Entry count (+0.2 per entry, max +0.4 at 5+ entries)
  size_t entry_count = candidate.GetEntryCount();
  confidence += std::min(0.4f, entry_count * 0.08f);

  // Factor 2: Address proximity (+0.2 if all within 4KB)
  if (!candidate.targets.empty()) {
    uint32_t min_addr = *std::min_element(candidate.targets.begin(),
                                          candidate.targets.end());
    uint32_t max_addr = *std::max_element(candidate.targets.begin(),
                                          candidate.targets.end());
    if (max_addr - min_addr <= 4096) {
      confidence += 0.2f;
    }
  }

  // Factor 3: Code validation (+0.3 if >80% pass IsLikelyCode())
  int valid_code_targets = 0;
  for (uint32_t target : candidate.targets) {
    if (IsLikelyCode(target, 16)) {
      valid_code_targets++;
    }
  }
  float valid_ratio = static_cast<float>(valid_code_targets) /
                      static_cast<float>(candidate.targets.size());
  if (valid_ratio > 0.8f) {
    confidence += 0.3f;
  } else if (valid_ratio > 0.5f) {
    confidence += 0.15f;  // Partial credit
  }

  // Factor 4: Alignment (+0.1 if all addresses are even)
  bool all_even = true;
  for (uint32_t target : candidate.targets) {
    if (target % 2 != 0) {
      all_even = false;
      break;
    }
  }
  if (all_even) {
    confidence += 0.1f;
  }

  return confidence;
}

bool CodeAnalyzer::ValidateJumpTable(const JumpTableCandidate& candidate,
                                    core::AddressMap* address_map) const {
  // Check confidence threshold
  if (candidate.confidence < MIN_CONFIDENCE) {
    return false;
  }

  // Check entry count range
  size_t entry_count = candidate.GetEntryCount();
  if (entry_count < MIN_JUMP_TABLE_ENTRIES ||
      entry_count > MAX_JUMP_TABLE_ENTRIES) {
    return false;
  }

  // Check all targets are within binary bounds
  for (uint32_t target : candidate.targets) {
    if (!IsValidAddress(target)) {
      return false;
    }
  }

  // Check that targets don't point to DATA regions
  for (uint32_t target : candidate.targets) {
    if (address_map->GetType(target) == core::AddressType::DATA) {
      return false;  // Target points to known DATA
    }
  }

  // At least 50% of targets should validate as likely code
  int valid_targets = 0;
  for (uint32_t target : candidate.targets) {
    if (IsLikelyCode(target, 16)) {
      valid_targets++;
    }
  }
  float valid_ratio = static_cast<float>(valid_targets) /
                      static_cast<float>(candidate.targets.size());
  if (valid_ratio < 0.5f) {
    return false;
  }

  return true;
}

void CodeAnalyzer::ProcessJumpTable(const JumpTableCandidate& table,
                                    core::AddressMap* address_map) {
  // Mark table itself as DATA
  for (uint32_t addr = table.start_address; addr <= table.end_address; ++addr) {
    address_map->SetType(addr, core::AddressType::DATA);
  }

  // Annotate table start with metadata for formatter
  // Use special comment marker that formatter can recognize
  std::string comment = "JUMPTABLE:" + std::to_string(table.GetEntryCount());
  address_map->SetComment(table.start_address, comment);

  // Add targets as entry points
  for (uint32_t target : table.targets) {
    if (IsValidAddress(target)) {
      discovered_entry_points_.insert(target);
      address_map->AddXref(target, table.start_address);
    }
  }

  LOG_INFO("Jump table at $" + std::to_string(table.start_address) +
           ": " + std::to_string(table.GetEntryCount()) + " entries, " +
           "confidence " + std::to_string(table.confidence));
}

void CodeAnalyzer::ScanForJumpTables(core::AddressMap* address_map) {
  LOG_INFO("Scanning for jump tables...");

  // Find all candidates (skips CODE regions)
  std::vector<JumpTableCandidate> candidates = FindJumpTableCandidates(address_map);

  LOG_DEBUG("Found " + std::to_string(candidates.size()) + " jump table candidate(s)");

  // Calculate confidence for each candidate
  for (auto& candidate : candidates) {
    candidate.confidence = CalculateTableConfidence(candidate);
  }

  // Validate and process high-confidence tables
  int processed_count = 0;
  for (const auto& candidate : candidates) {
    if (ValidateJumpTable(candidate, address_map)) {
      ProcessJumpTable(candidate, address_map);
      processed_count++;
    } else {
      LOG_DEBUG("Rejected jump table candidate at $" +
                std::to_string(candidate.start_address) +
                " (confidence: " + std::to_string(candidate.confidence) + ")");
    }
  }

  LOG_INFO("Processed " + std::to_string(processed_count) + " jump table(s)");
}

// =============================================================================
// Misalignment Detection and Resolution
// =============================================================================

bool CodeAnalyzer::IsInstructionBoundary(uint32_t address) const {
  // Delegate to MisalignmentResolver (WP-01 Phase 3)
  return misalignment_resolver_->IsInstructionBoundary(address);
}

bool CodeAnalyzer::DetectMisalignment(uint32_t target_address,
                                     core::AddressMap* address_map) {
  // Delegate to MisalignmentResolver (WP-01 Phase 3)
  return misalignment_resolver_->DetectMisalignment(target_address, address_map);
}

uint32_t CodeAnalyzer::FindPreviousInstructionBoundary(uint32_t address) const {
  // Delegate to MisalignmentResolver (WP-01 Phase 3)
  return misalignment_resolver_->FindPreviousInstructionBoundary(address);
}

float CodeAnalyzer::CalculateInstructionConfidence(uint32_t address,
                                                   core::AddressMap* address_map) const {
  // Delegate to MisalignmentResolver (WP-01 Phase 3)
  return misalignment_resolver_->CalculateInstructionConfidence(address, address_map);
}

bool CodeAnalyzer::ResolveMisalignment(uint32_t target_address,
                                       uint32_t source_address,
                                       bool is_unconditional_branch,
                                       core::AddressMap* address_map) {
  // Delegate to MisalignmentResolver (WP-01 Phase 3)
  return misalignment_resolver_->ResolveMisalignment(
      target_address, source_address, is_unconditional_branch, address_map,
      &discovered_entry_points_, &visited_recursive_);
}

void CodeAnalyzer::ClearVisitedRange(uint32_t start, uint32_t end) {
  // Delegate to MisalignmentResolver (WP-01 Phase 3)
  misalignment_resolver_->ClearVisitedRange(start, end, &visited_recursive_);
}

void CodeAnalyzer::InvalidateConflictingInstructions(uint32_t target_address,
                                                     core::AddressMap* address_map) {
  // Delegate to MisalignmentResolver (WP-01 Phase 3)
  misalignment_resolver_->InvalidateConflictingInstructions(
      target_address, address_map, &visited_recursive_);
}

bool CodeAnalyzer::DetectAndResolvePostPassMisalignments(core::AddressMap* address_map) {
  // Delegate to MisalignmentResolver (WP-01 Phase 3)
  return misalignment_resolver_->DetectAndResolvePostPassMisalignments(
      address_map, &discovered_entry_points_, &visited_recursive_);
}

void CodeAnalyzer::DynamicAnalysis(core::AddressMap* address_map) {
  LOG_INFO("Starting dynamic analysis (execution simulation)...");

  ExecutionSimulator simulator(cpu_, binary_);

  int addresses_discovered = 0;

  // Simulate from each entry point
  for (uint32_t ep : entry_points_) {
    std::set<uint32_t> discovered = simulator.SimulateFrom(ep, 500);

    // Add ALL discovered addresses as entry points (may resolve misalignments)
    for (uint32_t addr : discovered) {
      if (IsValidAddress(addr) && !discovered_entry_points_.count(addr)) {
        std::stringstream ss;
        ss << std::hex << std::uppercase << "$" << addr;
        LOG_INFO("Dynamic analysis discovered new entry point: " + ss.str());

        discovered_entry_points_.insert(addr);
        addresses_discovered++;
      }
    }
  }

  // Also simulate from previously discovered entry points
  std::set<uint32_t> initial_discovered = discovered_entry_points_;
  for (uint32_t ep : initial_discovered) {
    std::set<uint32_t> discovered = simulator.SimulateFrom(ep, 500);

    for (uint32_t addr : discovered) {
      if (IsValidAddress(addr) && !discovered_entry_points_.count(addr)) {
        std::stringstream ss;
        ss << std::hex << std::uppercase << "$" << addr;
        LOG_INFO("Dynamic analysis discovered new entry point: " + ss.str());

        discovered_entry_points_.insert(addr);
        addresses_discovered++;
      }
    }
  }

  std::stringstream ss;
  ss << "Dynamic analysis complete: " << addresses_discovered << " new entry points discovered";
  LOG_INFO(ss.str());
}

}  // namespace analysis
}  // namespace sourcerer
