// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "analysis/strategies/reclassification_strategy.h"

#include <algorithm>
#include <sstream>

#include "core/constants.h"
#include "utils/logger.h"

namespace sourcerer {
namespace analysis {

ReclassificationStrategy::ReclassificationStrategy(
    cpu::CpuPlugin* cpu,
    const core::Binary* binary,
    DataHeuristics* data_heuristics)
    : cpu_(cpu),
      binary_(binary),
      data_heuristics_(data_heuristics) {}

bool ReclassificationStrategy::IsValidAddress(uint32_t address) const {
  uint32_t start = binary_->load_address();
  uint32_t end = start + binary_->size();
  return address >= start && address < end;
}

int ReclassificationStrategy::CountXrefsInRange(core::AddressMap* address_map,
                                                uint32_t start,
                                                uint32_t end) const {
  int count = 0;
  for (uint32_t addr = start; addr < end; ++addr) {
    if (address_map->HasXrefs(addr)) {
      count += address_map->GetXrefs(addr).size();
    }
  }
  return count;
}

void ReclassificationStrategy::ReclassifyAfterComputedJumps(
    core::AddressMap* address_map,
    const std::set<uint32_t>& entry_points) {
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
    } catch (const std::exception& e) {
      LOG_DEBUG("Disassembly failed at $" + std::to_string(addr) +
                ": " + e.what());
      addr++;
      continue;
    }

    // Check if this is a computed jump
    if (inst.is_jump && !inst.is_branch &&
        inst.mode == core::AddressingMode::INDEXED) {
      // Found computed jump - mark unreachable bytes after it as DATA
      uint32_t after_jump = addr + inst.bytes.size();

      LOG_DEBUG("Found computed jump at $" + std::to_string(addr) +
               ", scanning for unreachable bytes");

      // Track which addresses we've reclassified in THIS scan
      // so we don't count xrefs from already-reclassified unreachable code
      std::set<uint32_t> reclassified_addrs;

      int reclassified = 0;
      for (size_t i = 0; i < constants::kMaxDataScan && (after_jump + i) < end; ++i) {
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
          if (xref_source >= (after_jump + constants::kMaxDataScan)) {
            has_reachable_xref = true;
            break;
          }
          // CRITICAL: If xref comes from inside the scan window, it's likely
          // also unreachable. There are two cases:
          // 1. Source was already reclassified → definitely unreachable
          // 2. Source is ahead of current position → assume unreachable
          // 3. Source is behind current position and still CODE → might be reachable,
          //    but only if it's not going to be reclassified later
          if (xref_source >= after_jump && xref_source < (after_jump + constants::kMaxDataScan)) {
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

void ReclassificationStrategy::ReclassifyMixedCodeDataRegions(
    core::AddressMap* address_map,
    std::map<uint32_t, core::Instruction>* instruction_cache,
    std::set<uint32_t>* visited_recursive) {
  // Detect CODE regions that contain instruction gaps - these are mixed CODE/DATA
  // A gap is a byte marked as CODE but not covered by any disassembled instruction

  uint32_t start = binary_->load_address();
  uint32_t end = start + binary_->size();

  // CRITICAL: Rebuild instruction cache by re-disassembling all CODE regions
  // The cache may have been cleared during analysis passes
  instruction_cache->clear();

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
        (*instruction_cache)[addr] = inst;
        addr += inst.bytes.size();
      } else {
        // Invalid instruction at CODE address (potential phantom)
        addr++;
      }
    } catch (const std::exception& e) {
      LOG_DEBUG("Disassembly failed at CODE address $" + std::to_string(addr) +
                ": " + e.what());
      // Disassembly failed at CODE address (potential phantom)
      addr++;
    }
  }

  LOG_DEBUG("Rebuilt instruction cache: " +
            std::to_string(instruction_cache->size()) + " instructions");

  // Build a map of which CODE bytes are actually part of instructions
  std::set<uint32_t> instruction_bytes;
  for (const auto& pair : *instruction_cache) {
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
        visited_recursive->erase(clear_addr);
      }

      ss.str("");
      ss << "Reclassified $" << code_start << "-$" << code_end << " as DATA";
      LOG_INFO(ss.str());
    }
  }
}

void ReclassificationStrategy::ReclassifyDataRegions(
    core::AddressMap* address_map,
    const std::set<uint32_t>& entry_points) {
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
    const uint32_t window_size = constants::kMinDataRegionSize;

    addr = code_block_start;
    while (addr < code_block_end) {
      uint32_t window_end = std::min(addr + window_size, code_block_end);

      // For regions at least MIN_DATA_REGION_SIZE bytes
      if (window_end - addr >= window_size) {
        // Count how many heuristics match
        int heuristic_matches = data_heuristics_->CountDataHeuristics(addr, window_end - 1);

        // Check cross-references
        int xref_count = CountXrefsInRange(address_map, addr, window_end);

        // Only reclassify if:
        // 1. At least MIN_HEURISTIC_MATCHES heuristics match
        // 2. No incoming cross-references
        // 3. Region is at least MIN_DATA_REGION_SIZE bytes
        // 4. No entry points in region
        if (heuristic_matches >= constants::kMinHeuristicMatches && xref_count == 0) {
          // Extend region
          uint32_t data_end = window_end;
          while (data_end < code_block_end && address_map->IsCode(data_end)) {
            int extended_matches = data_heuristics_->CountDataHeuristics(addr, data_end);
            if (extended_matches < constants::kMinHeuristicMatches) break;
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
          for (uint32_t ep : entry_points) {
            if (ep >= addr && ep < data_end) {
              contains_entry_point = true;
              break;
            }
          }

          if (!contains_entry_point && (data_end - addr) >= constants::kMinDataRegionSize) {
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

}  // namespace analysis
}  // namespace sourcerer
