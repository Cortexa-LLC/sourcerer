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
    : cpu_(cpu), binary_(binary) {
  // Register known platform-specific inline data routines
  // ProDOS MLI: JSR $BF00 followed by 1 byte (command) + 2 bytes (param pointer)
  known_inline_data_routines_[0xBF00] = 3;
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

  // Second pass: Reclassify CODE after computed jumps
  LOG_INFO("Running second pass: computed jump cleanup...");
  ReclassifyAfterComputedJumps(address_map);
  LOG_INFO("Computed jump cleanup complete");

  // Third pass: Reclassify CODE regions that look like data
  LOG_INFO("Running third pass: data region detection...");
  ReclassifyDataRegions(address_map);
  LOG_INFO("Third pass complete");
}

void CodeAnalyzer::AnalyzeFromQueue(core::AddressMap* address_map) {
  std::queue<uint32_t> queue;
  std::set<uint32_t> visited;

  // Initialize queue with entry points
  for (uint32_t ep : entry_points_) {
    queue.push(ep);
  }

  // Process queue
  while (!queue.empty() && instruction_count_ < max_instructions_) {
    uint32_t address = queue.front();
    queue.pop();

    // Skip if already visited
    if (visited.count(address) > 0) {
      continue;
    }

    ProcessAddress(address, address_map, &queue, &visited);
  }

  if (instruction_count_ >= max_instructions_) {
    LOG_WARNING("Reached maximum instruction limit (" + 
                std::to_string(max_instructions_) + ")");
  }
}

void CodeAnalyzer::ProcessAddress(uint32_t address,
                                  core::AddressMap* address_map,
                                  std::queue<uint32_t>* queue,
                                  std::set<uint32_t>* visited) {
  // Mark as visited
  visited->insert(address);

  // Check if valid
  if (!IsValidAddress(address)) {
    return;
  }

  // Check if already marked as code
  if (address_map->IsCode(address)) {
    return;
  }

  try {
    // Disassemble instruction
    const uint8_t* data = binary_->GetPointer(address);
    size_t remaining = binary_->load_address() + binary_->size() - address;
    
    core::Instruction inst = cpu_->Disassemble(data, remaining, address);
    
    // Mark instruction bytes as code
    for (size_t i = 0; i < inst.bytes.size(); ++i) {
      uint32_t addr = address + i;
      if (!address_map->IsCode(addr)) {
        address_map->SetType(addr, core::AddressType::CODE);
        code_bytes_++;
      }
    }
    
    instruction_count_++;
    
    LOG_DEBUG("Disassembled at $" + std::to_string(address) + 
              ": " + inst.mnemonic + " " + inst.operand);

    // Handle branches and jumps
    if (inst.target_address != 0) {
      // Add cross-reference
      address_map->AddXref(inst.target_address, address);

      if (inst.is_branch || inst.is_jump || inst.is_call) {
        // Add target to queue if it's within bounds
        if (IsValidAddress(inst.target_address)) {
          queue->push(inst.target_address);
          LOG_DEBUG("  -> Queued target: $" + std::to_string(inst.target_address));
        }
      }
    }

    // Decide if we should continue to next instruction
    bool should_stop = ShouldStopPath(inst);

    // Note: We don't mark bytes as DATA here during code flow analysis
    // because xrefs haven't been fully built yet. Instead, we do this
    // in the post-processing pass (ReclassifyAfterComputedJumps).

    if (!should_stop) {
      // Special handling for JSR to inline data routines
      if (inst.is_call && inst.target_address != 0) {
        // Check if target is a known platform-specific inline data routine (e.g., ProDOS MLI)
        auto it = known_inline_data_routines_.find(inst.target_address);
        if (it != known_inline_data_routines_.end()) {
          // Mark the inline data bytes as DATA
          uint32_t inline_data_addr = address + inst.bytes.size();
          size_t inline_data_size = it->second;

          LOG_DEBUG("  -> Detected known inline data routine at $" +
                   std::to_string(inst.target_address) +
                   ", marking " + std::to_string(inline_data_size) + " bytes as DATA");

          for (size_t i = 0; i < inline_data_size && IsValidAddress(inline_data_addr + i); ++i) {
            address_map->SetType(inline_data_addr + i, core::AddressType::INLINE_DATA);
            data_bytes_++;
          }

          // Continue code flow after inline data
          uint32_t after_data = inline_data_addr + inline_data_size;
          if (IsValidAddress(after_data)) {
            queue->push(after_data);
            LOG_DEBUG("  -> Continue code flow after inline data at $" +
                     std::to_string(after_data));
          }
        } else if (IsInlineDataRoutine(inst.target_address, address_map)) {
          // Check if target routine uses inline data pattern (heuristic detection)
          // Scan inline data after JSR
          uint32_t after_data = ScanInlineData(address + inst.bytes.size(),
                                               address_map);
          if (after_data != 0) {
            // Continue code flow after inline data
            if (IsValidAddress(after_data)) {
              queue->push(after_data);
              LOG_DEBUG("  -> Continue after inline data at $" +
                       std::to_string(after_data));
            }
          } else {
            // No terminator found, continue normally
            uint32_t next_address = address + inst.bytes.size();
            if (IsValidAddress(next_address)) {
              queue->push(next_address);
            }
          }
        } else {
          // Normal JSR, continue to next instruction
          uint32_t next_address = address + inst.bytes.size();
          if (IsValidAddress(next_address)) {
            queue->push(next_address);
          }
        }
      } else {
        // Continue to next instruction
        uint32_t next_address = address + inst.bytes.size();
        if (IsValidAddress(next_address)) {
          queue->push(next_address);
        }
      }
    } else {
      LOG_DEBUG("  -> Stopped path (return/unconditional jump)");
    }

  } catch (const std::exception& e) {
    LOG_ERROR("Failed to disassemble at $" + std::to_string(address) + 
              ": " + e.what());
  }
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
      } catch (...) {
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
    return best_addr;
  }

  // No valid sequence found, return original address
  LOG_WARNING("No valid instruction sequence found in first " + std::to_string(MAX_SCAN) +
              " bytes, using original entry point");
  return start_address;
}

bool CodeAnalyzer::ShouldStopPath(const core::Instruction& inst) const {
  // Stop on returns (RTS, RTI)
  if (inst.is_return) {
    return true;
  }

  // Stop on unconditional jumps (JMP absolute or indexed)
  // But NOT on conditional branches (BEQ, BNE, etc.)
  if (inst.is_jump && !inst.is_branch) {
    // Special case: computed jumps (JMP with indexed addressing)
    // These use jump tables and we can't follow them statically
    // Examples: JMP ,X  JMP A,X  JMP [,X]
    if (inst.mode == core::AddressingMode::INDEXED) {
      // Computed jump - cannot follow statically
      return true;
    }
    return true;
  }

  // Stop on illegal/unknown opcodes (likely data, not code)
  if (inst.is_illegal) {
    return true;
  }

  // BRK instruction should also stop
  if (inst.mnemonic == "BRK") {
    return true;
  }

  return false;
}

bool CodeAnalyzer::IsInlineDataRoutine(uint32_t address,
                                       core::AddressMap* address_map) {
  (void)address_map;  // Reserved for future use
  // Check if we've already identified this routine
  if (inline_data_routines_.count(address) > 0) {
    return true;
  }

  // Scan first few instructions of subroutine for inline data pattern:
  // Pattern: PLA, STA/STX/STY (save return address), ... read data ...,
  //          LDA/LDX/LDY, PHA (restore adjusted return address), RTS

  if (!IsValidAddress(address)) {
    return false;
  }

  try {
    const uint8_t* data = binary_->GetPointer(address);
    size_t remaining = binary_->load_address() + binary_->size() - address;

    // Check first instruction - should pull return address (PLA or TSX)
    core::Instruction inst1 = cpu_->Disassemble(data, remaining, address);
    if (inst1.mnemonic != "PLA" && inst1.mnemonic != "TSX") {
      return false;
    }

    // If we see PLA at start, it's likely an inline data routine
    // Add to our tracking set
    inline_data_routines_.insert(address);
    LOG_DEBUG("Detected inline data routine at $" + std::to_string(address));
    return true;

  } catch (const std::exception&) {
    return false;
  }
}

uint32_t CodeAnalyzer::ScanInlineData(uint32_t start_address,
                                      core::AddressMap* address_map) {
  // Scan forward from start_address to find data terminator (usually $00)
  // Mark encountered bytes as data
  // Return address after terminator

  uint32_t addr = start_address;
  const size_t max_data_size = 256;  // Safety limit
  size_t count = 0;

  while (IsValidAddress(addr) && count < max_data_size) {
    const uint8_t* data = binary_->GetPointer(addr);
    if (!data) break;

    uint8_t byte = *data;

    // Mark as data
    if (!address_map->IsCode(addr)) {
      address_map->SetType(addr, core::AddressType::INLINE_DATA);
      data_bytes_++;
    }

    // Check for terminator (0x00)
    if (byte == 0x00) {
      LOG_DEBUG("Found inline data: $" + std::to_string(start_address) +
                " to $" + std::to_string(addr) + " (" +
                std::to_string(count + 1) + " bytes)");
      return addr + 1;  // Return address after terminator
    }

    addr++;
    count++;
  }

  LOG_WARNING("No terminator found for inline data at $" +
              std::to_string(start_address));
  return 0;  // No valid terminator found
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
    } catch (...) {
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
    } catch (...) {
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

float CodeAnalyzer::CalculatePrintablePercentage(uint32_t start, uint32_t end) const {
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

// NEW: Conservative reclassification helper methods
int CodeAnalyzer::CountXrefsInRange(core::AddressMap* address_map,
                                    uint32_t start, uint32_t end) const {
  int count = 0;
  for (uint32_t addr = start; addr < end; ++addr) {
    if (address_map->HasXrefs(addr)) {
      count += address_map->GetXrefs(addr).size();
    }
  }
  return count;
}

bool CodeAnalyzer::HasLongPrintableSequence(uint32_t start, uint32_t end) const {
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

bool CodeAnalyzer::HasNullTerminatedStrings(uint32_t start, uint32_t end) const {
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

bool CodeAnalyzer::HasRepeatedBytes(uint32_t start, uint32_t end) const {
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

bool CodeAnalyzer::HasAddressLikePairs(uint32_t start, uint32_t end) const {
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

bool CodeAnalyzer::HasRepeatedInstructions(uint32_t start, uint32_t end) const {
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
    } catch (...) {
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

bool CodeAnalyzer::HasBitmapEntropy(uint32_t start, uint32_t end) const {
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

bool CodeAnalyzer::HasByteAlignment(uint32_t start, uint32_t end) const {
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

bool CodeAnalyzer::IsInGraphicsRegion(uint32_t start, uint32_t end) const {
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

  // CoCo semi-graphics and character ROM locations are not in binary

  return false;
}

bool CodeAnalyzer::HasSpritePatterns(uint32_t start, uint32_t end) const {
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

  // Sprite data usually has a mix of zero/FF bytes (background) and sparse bytes (pixels)
  float zero_ratio = static_cast<float>(zero_byte_count) / static_cast<float>(region_size);
  float sparse_ratio = static_cast<float>(sparse_byte_count) / static_cast<float>(region_size);

  // Typical sprite data: 20-60% background, 10-40% sparse pixels
  return (zero_ratio >= 0.2f && zero_ratio <= 0.6f) &&
         (sparse_ratio >= 0.1f && sparse_ratio <= 0.4f);
}

int CodeAnalyzer::CountDataHeuristics(uint32_t start, uint32_t end) const {
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

  // Heuristic 7: High illegal opcode density
  if (HasHighIllegalDensity(start, end)) {
    count++;
  }

  // NEW Heuristic 8: Bitmap entropy (graphics data)
  if (HasBitmapEntropy(start, end)) {
    count++;
  }

  // NEW Heuristic 9: Byte alignment patterns (character/sprite data)
  if (HasByteAlignment(start, end)) {
    count++;
  }

  // NEW Heuristic 10: Platform-specific graphics regions
  if (IsInGraphicsRegion(start, end)) {
    count++;
  }

  // NEW Heuristic 11: Sprite/character patterns
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
    if (address == 0x7937) {
      std::cerr << "DEBUG: Skipping $7937 (already visited in pass " << passes_completed_ << ")" << std::endl;
    }
    return;
  }

  // Skip if outside binary bounds
  if (!IsValidAddress(address)) {
    if (address == 0x7937) {
      std::cerr << "DEBUG: Skipping $7937 (invalid address in pass " << passes_completed_ << ")" << std::endl;
    }
    return;
  }

  // Skip if already confirmed as DATA
  if (address_map->GetType(address) == core::AddressType::DATA) {
    if (address == 0x7937) {
      std::cerr << "DEBUG: Skipping $7937 (marked as DATA in pass " << passes_completed_ << ")" << std::endl;
    }
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
    } catch (...) {
      // Mark as DATA and stop this path
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

        // Debug: track $7937
        if (current + i == 0x7937) {
          std::cerr << "DEBUG: Marked $7937 as CODE in pass " << passes_completed_
                    << " inst: " << inst.mnemonic << " at $" << std::hex << current << std::dec << std::endl;
        }
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
      // Debug: track branch at $792D
      if (current == 0x792D) {
        std::cerr << "DEBUG: Branch at $792D, target_address=$" << std::hex << inst.target_address
                  << " in pass " << std::dec << passes_completed_ << std::endl;
      }

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

          // Debug: track $7937
          if (inst.target_address == 0x7937) {
            std::cerr << "DEBUG: Misalignment at $7937, should_follow=" << should_follow
                      << " in pass " << passes_completed_ << std::endl;
          }
        }

        // RECURSIVE: Follow branch target if resolved or no conflict
        if (should_follow) {
          // Debug: track $7937
          if (inst.target_address == 0x7937) {
            std::cerr << "DEBUG: Following branch to $7937 from $" << std::hex << current
                      << " in pass " << std::dec << passes_completed_ << std::endl;
          }
          AnalyzeRecursively(inst.target_address, address_map, depth + 1);
        } else if (inst.target_address == 0x7937) {
          std::cerr << "DEBUG: NOT following branch to $7937 from $" << std::hex << current
                    << " in pass " << std::dec << passes_completed_ << std::endl;
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
  if (!IsValidAddress(address)) return false;

  // Delegate to CPU plugin (SOLID architecture)
  const uint8_t* data = binary_->GetPointer(address);
  size_t remaining = binary_->load_address() + binary_->size() - address;

  return cpu_->IsLikelyCode(data, remaining, address, scan_length);
}

bool CodeAnalyzer::LooksLikeSubroutineStart(uint32_t address) const {
  if (!IsValidAddress(address)) return false;

  // Delegate to CPU plugin (SOLID architecture)
  const uint8_t* data = binary_->GetPointer(address);
  size_t remaining = binary_->load_address() + binary_->size() - address;

  return cpu_->LooksLikeSubroutineStart(data, remaining, address);
}

void CodeAnalyzer::ScanInterruptVectors() {
  // Get CPU-specific interrupt vectors (SOLID architecture)
  cpu::AnalysisCapabilities caps = cpu_->GetAnalysisCapabilities();
  if (!caps.has_interrupt_vectors) {
    return;  // CPU doesn't have interrupt vectors
  }

  std::vector<cpu::InterruptVector> vectors = cpu_->GetInterruptVectors();

  for (const auto& vec : vectors) {
    uint32_t vec_addr = vec.address;
    if (!IsValidAddress(vec_addr) || !IsValidAddress(vec_addr + 1)) continue;

    const uint8_t* data = binary_->GetPointer(vec_addr);
    size_t size = binary_->load_address() + binary_->size() - vec_addr;

    // Let CPU plugin handle endianness
    uint32_t target = cpu_->ReadVectorTarget(data, size, 0);

    if (target != 0 && IsValidAddress(target) && IsLikelyCode(target)) {
      discovered_entry_points_.insert(target);
      LOG_DEBUG("Discovered " + vec.name + " vector at $" +
                std::to_string(vec_addr) + " -> $" + std::to_string(target));
    }
  }
}

void CodeAnalyzer::ScanForSubroutinePatterns(core::AddressMap* address_map) {
  // Scan UNKNOWN regions for potential subroutine entry points
  uint32_t start = binary_->load_address();
  uint32_t end = start + binary_->size();

  // Sample every N bytes to avoid excessive scanning
  const int SAMPLE_STRIDE = 4;  // Check every 4 bytes (compromise between coverage and speed)

  for (uint32_t addr = start; addr < end; addr += SAMPLE_STRIDE) {
    // Only check UNKNOWN regions (not already classified as CODE or DATA)
    if (address_map->GetType(addr) == core::AddressType::UNKNOWN) {
      if (LooksLikeSubroutineStart(addr)) {
        discovered_entry_points_.insert(addr);
        LOG_DEBUG("Discovered likely subroutine at $" + std::to_string(addr));
      }
    }
  }
}

// CoCo-specific entry point detection

bool CodeAnalyzer::IsCoCoCartridgeSpace(uint32_t address) const {
  // CoCo cartridge ROM space: $C000-$FEFF
  // Reset vector at $FFFE-$FFFF
  return (address >= 0xC000 && address <= 0xFEFF);
}

bool CodeAnalyzer::HasCoCoPreamble(uint32_t address) const {
  // Check for common CoCo machine language program preambles
  // Many programs start with:
  // - 2-byte load address (often skipped by loader)
  // - Then immediate executable code
  // - Or "DK" signature for Disk BASIC

  if (!IsValidAddress(address) || !IsValidAddress(address + 1)) {
    return false;
  }

  const uint8_t* data = binary_->GetPointer(address);
  if (!data) return false;

  // Check for "DK" signature (Disk BASIC)
  if (data[0] == 0x44 && data[1] == 0x4B) {
    return true;
  }

  // Check for common preamble patterns:
  // PSHS U,Y,X,DP,D,CC (full register save on entry)
  // Opcode: $34 followed by register mask
  if (data[0] == 0x34) {
    return true;
  }

  // ORCC #$50 (disable interrupts - common at program start)
  if (data[0] == 0x1A && data[1] == 0x50) {
    return true;
  }

  // LDS #immediate (set stack pointer - very common first instruction)
  if (data[0] == 0x10 && data[1] == 0xCE) {
    return true;
  }

  // JMP extended (redirect to real entry point)
  if (data[0] == 0x7E) {
    return true;
  }

  return false;
}

void CodeAnalyzer::ScanCoCoCartridgeEntryPoints() {
  // Cartridge programs typically have entry point at $C000
  uint32_t cart_entry = 0xC000;

  if (IsValidAddress(cart_entry) && IsCoCoCartridgeSpace(cart_entry)) {
    if (IsLikelyCode(cart_entry)) {
      discovered_entry_points_.insert(cart_entry);
      LOG_DEBUG("Discovered CoCo cartridge entry point at $C000");
    }
  }

  // Check if binary is loaded in cartridge space
  uint32_t load_addr = binary_->load_address();
  if (IsCoCoCartridgeSpace(load_addr)) {
    // Cartridge ROM - entry point is typically at start
    discovered_entry_points_.insert(load_addr);
    LOG_DEBUG("Binary in CoCo cartridge space, adding load address as entry point");
  }
}

void CodeAnalyzer::ScanCoCoStandardEntryPoints() {
  uint32_t load_addr = binary_->load_address();

  // Standard CoCo machine language program entry patterns:

  // Pattern 1: Load address + 0 (immediate entry)
  if (IsLikelyCode(load_addr)) {
    discovered_entry_points_.insert(load_addr);
    LOG_DEBUG("CoCo entry point at load address: $" + std::to_string(load_addr));
  }

  // Pattern 2: Load address + 2 (skip 2-byte preamble/header)
  if (IsValidAddress(load_addr + 2)) {
    const uint8_t* data = binary_->GetPointer(load_addr);
    if (data) {
      // Check if first 2 bytes look like a preamble
      // Common: $00 $xx, load address itself, or "EX" signature
      bool has_preamble = (data[0] == 0x00) ||
                          (data[0] == 0x45 && data[1] == 0x58) ||  // "EX"
                          (data[0] == ((load_addr >> 8) & 0xFF));

      if (has_preamble && IsLikelyCode(load_addr + 2)) {
        discovered_entry_points_.insert(load_addr + 2);
        LOG_DEBUG("CoCo entry point after 2-byte preamble: $" +
                  std::to_string(load_addr + 2));
      }
    }
  }

  // Pattern 3: Check for DK header (Disk BASIC format)
  // Disk BASIC programs often have "DK" at offset 0
  if (IsValidAddress(load_addr) && IsValidAddress(load_addr + 1)) {
    const uint8_t* data = binary_->GetPointer(load_addr);
    if (data && data[0] == 0x44 && data[1] == 0x4B) {  // "DK"
      // Entry point typically at offset $09
      if (IsValidAddress(load_addr + 0x09)) {
        discovered_entry_points_.insert(load_addr + 0x09);
        LOG_DEBUG("CoCo Disk BASIC format detected, entry at +$09");
      }
    }
  }

  // Pattern 4: Scan for PSHS as subroutine entry markers
  // Many CoCo programs use PSHS U,Y,X,... as subroutine prologues
  uint32_t end = load_addr + binary_->size();
  for (uint32_t addr = load_addr; addr < end - 1; addr += 2) {
    const uint8_t* data = binary_->GetPointer(addr);
    if (!data) continue;

    // PSHS with multiple registers (opcode $34, mask with multiple bits set)
    if (data[0] == 0x34) {
      uint8_t mask = data[1];
      int bit_count = 0;
      for (int i = 0; i < 8; ++i) {
        if (mask & (1 << i)) bit_count++;
      }

      // If saving 3+ registers, likely a subroutine entry
      if (bit_count >= 3 && IsLikelyCode(addr)) {
        discovered_entry_points_.insert(addr);
        LOG_DEBUG("CoCo subroutine entry (PSHS) at $" + std::to_string(addr));
      }
    }
  }

  // Pattern 5: Look for addresses in the binary that point to code
  // (potential jump tables or dispatch tables)
  for (uint32_t addr = load_addr; addr < end - 1; addr += 2) {
    const uint8_t* data = binary_->GetPointer(addr);
    if (!data) continue;

    // Read 16-bit address (6809 is big-endian)
    uint16_t target = (data[0] << 8) | data[1];

    // Check if this points within the binary and looks like code
    if (IsValidAddress(target) && IsLikelyCode(target)) {
      // Additional validation: target should be aligned and not in data region
      if ((target % 2) == 0) {  // Code typically even-aligned
        discovered_entry_points_.insert(target);
        LOG_DEBUG("CoCo potential code pointer at $" + std::to_string(addr) +
                  " -> $" + std::to_string(target));
      }
    }
  }
}

void CodeAnalyzer::DiscoverEntryPoints(core::AddressMap* address_map) {
  LOG_INFO("Discovering additional entry points...");

  int initial_count = discovered_entry_points_.size();

  // Scan CPU-specific interrupt vectors (SOLID architecture)
  ScanInterruptVectors();

  // CoCo-specific entry point detection
  if (cpu_->GetVariant() == cpu::CpuVariant::MOTOROLA_6809) {
    ScanCoCoCartridgeEntryPoints();
    ScanCoCoStandardEntryPoints();
  }

  // Scan for subroutine patterns in UNKNOWN regions
  ScanForSubroutinePatterns(address_map);

  int new_count = discovered_entry_points_.size() - initial_count;
  LOG_INFO("Discovered " + std::to_string(new_count) +
           " additional entry point(s)");
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
  return instruction_cache_.find(address) != instruction_cache_.end();
}

bool CodeAnalyzer::DetectMisalignment(uint32_t target_address,
                                     core::AddressMap* address_map) {
  // Check if target is CODE but NOT at an instruction boundary
  if (!address_map->IsCode(target_address)) {
    return false;  // Not CODE, no misalignment
  }

  if (IsInstructionBoundary(target_address)) {
    return false;  // Valid boundary, no misalignment
  }

  // Target is CODE but not at instruction start = misalignment!
  return true;
}

uint32_t CodeAnalyzer::FindPreviousInstructionBoundary(uint32_t address) const {
  // Search backwards in cache for closest instruction boundary
  uint32_t closest = 0;

  for (const auto& pair : instruction_cache_) {
    uint32_t inst_addr = pair.first;
    const core::Instruction& inst = pair.second;

    // Check if this instruction overlaps with target address
    uint32_t inst_end = inst_addr + inst.bytes.size();
    if (inst_addr <= address && address < inst_end) {
      return inst_addr;  // Found the instruction containing this address
    }
  }

  return closest;
}

float CodeAnalyzer::CalculateInstructionConfidence(uint32_t address,
                                                   core::AddressMap* address_map) const {
  float confidence = 0.5f;  // Baseline

  // Try to disassemble a sequence of instructions from this address
  uint32_t current = address;
  int valid_sequence = 0;
  const int SEQUENCE_LENGTH = 5;

  // Track instruction frequency patterns
  int rare_instruction_count = 0;
  int common_instruction_count = 0;
  int suspicious_pattern_count = 0;

  for (int i = 0; i < SEQUENCE_LENGTH; ++i) {
    if (!IsValidAddress(current)) break;

    const uint8_t* data = binary_->GetPointer(current);
    size_t remaining = binary_->load_address() + binary_->size() - current;
    if (!data || remaining == 0) break;

    core::Instruction inst;
    try {
      inst = cpu_->Disassemble(data, remaining, current);
    } catch (...) {
      break;
    }

    if (inst.bytes.empty() || inst.is_illegal) break;

    valid_sequence++;

    // ========== INSTRUCTION FREQUENCY ANALYSIS ==========

    // VERY COMMON: Load/Store/Transfer (highest frequency in typical code)
    if (inst.mnemonic == "LDA" || inst.mnemonic == "LDB" || inst.mnemonic == "LDD" ||
        inst.mnemonic == "LDX" || inst.mnemonic == "LDY" || inst.mnemonic == "LDU" ||
        inst.mnemonic == "STA" || inst.mnemonic == "STB" || inst.mnemonic == "STD" ||
        inst.mnemonic == "STX" || inst.mnemonic == "STY" || inst.mnemonic == "STU" ||
        inst.mnemonic == "TFR" || inst.mnemonic == "EXG") {
      confidence += 0.08f;
      common_instruction_count++;
    }
    // VERY COMMON: Arithmetic/Logic
    else if (inst.mnemonic == "ADDA" || inst.mnemonic == "ADDB" || inst.mnemonic == "ADDD" ||
             inst.mnemonic == "SUBA" || inst.mnemonic == "SUBB" || inst.mnemonic == "SUBD" ||
             inst.mnemonic == "CMPA" || inst.mnemonic == "CMPB" || inst.mnemonic == "CMPD" ||
             inst.mnemonic == "CMPX" || inst.mnemonic == "CMPY" ||
             inst.mnemonic == "ANDA" || inst.mnemonic == "ANDB" || inst.mnemonic == "ANDCC" ||
             inst.mnemonic == "ORA" || inst.mnemonic == "ORB" || inst.mnemonic == "ORCC" ||
             inst.mnemonic == "EORA" || inst.mnemonic == "EORB") {
      confidence += 0.08f;
      common_instruction_count++;
    }
    // VERY COMMON: Stack operations (especially at subroutine entry/exit)
    else if (inst.mnemonic == "PSHS" || inst.mnemonic == "PULS" ||
             inst.mnemonic == "PSHU" || inst.mnemonic == "PULU") {
      if (i == 0) {
        confidence += 0.20f;  // VERY likely at branch target
      } else {
        confidence += 0.10f;
      }
      common_instruction_count++;
    }
    // VERY COMMON: Branches and subroutine calls
    else if (inst.mnemonic == "BEQ" || inst.mnemonic == "BNE" || inst.mnemonic == "BCC" ||
             inst.mnemonic == "BCS" || inst.mnemonic == "BVC" || inst.mnemonic == "BVS" ||
             inst.mnemonic == "BPL" || inst.mnemonic == "BMI" || inst.mnemonic == "BGE" ||
             inst.mnemonic == "BLT" || inst.mnemonic == "BGT" || inst.mnemonic == "BLE" ||
             inst.mnemonic == "BHI" || inst.mnemonic == "BLS" || inst.mnemonic == "BRA" ||
             inst.mnemonic == "BSR" || inst.mnemonic == "JSR" || inst.mnemonic == "LBRA" ||
             inst.mnemonic == "LBSR") {
      confidence += 0.05f;
      common_instruction_count++;
    }
    // COMMON: Return, increment/decrement, shift/rotate
    else if (inst.mnemonic == "RTS" || inst.mnemonic == "RTI" ||
             inst.mnemonic == "INCA" || inst.mnemonic == "INCB" || inst.mnemonic == "INC" ||
             inst.mnemonic == "DECA" || inst.mnemonic == "DECB" || inst.mnemonic == "DEC" ||
             inst.mnemonic == "LSLA" || inst.mnemonic == "LSLB" || inst.mnemonic == "LSL" ||
             inst.mnemonic == "LSRA" || inst.mnemonic == "LSRB" || inst.mnemonic == "LSR" ||
             inst.mnemonic == "ASRA" || inst.mnemonic == "ASRB" || inst.mnemonic == "ASR" ||
             inst.mnemonic == "ROLA" || inst.mnemonic == "ROLB" || inst.mnemonic == "ROL" ||
             inst.mnemonic == "RORA" || inst.mnemonic == "RORB" || inst.mnemonic == "ROR") {
      confidence += 0.05f;
      common_instruction_count++;
    }
    // COMMON: Test, clear, negate
    else if (inst.mnemonic == "TSTA" || inst.mnemonic == "TSTB" || inst.mnemonic == "TST" ||
             inst.mnemonic == "CLRA" || inst.mnemonic == "CLRB" || inst.mnemonic == "CLR" ||
             inst.mnemonic == "NEGA" || inst.mnemonic == "NEGB" || inst.mnemonic == "NEG" ||
             inst.mnemonic == "COMA" || inst.mnemonic == "COMB" || inst.mnemonic == "COM") {
      confidence += 0.05f;
      common_instruction_count++;
    }
    // COMMON: LEA operations (address calculation)
    else if (inst.mnemonic == "LEAX" || inst.mnemonic == "LEAY" ||
             inst.mnemonic == "LEAS" || inst.mnemonic == "LEAU") {
      confidence += 0.05f;
      common_instruction_count++;
    }
    // RARE: Software interrupts (should be infrequent in typical code)
    else if (inst.mnemonic == "SWI" || inst.mnemonic == "SWI2" || inst.mnemonic == "SWI3") {
      confidence -= 0.15f;
      rare_instruction_count++;

      // VERY suspicious if SWI appears early in sequence
      if (i < 3) {
        confidence -= 0.15f;  // Extra penalty
        suspicious_pattern_count++;
      }
    }
    // RARE: Synchronization and wait instructions
    else if (inst.mnemonic == "SYNC" || inst.mnemonic == "CWAI") {
      confidence -= 0.10f;
      rare_instruction_count++;
    }
    // RARE: Multiply/divide (less common in typical 6809 code)
    else if (inst.mnemonic == "MUL" || inst.mnemonic == "DIV") {
      // Don't penalize, but don't boost either (neutral)
    }
    // MODERATE: Other instructions (SEX, DAA, ABX, etc.)
    else {
      confidence += 0.02f;  // Small boost for valid instruction
    }

    // ========== PATTERN ANALYSIS ==========

    // Suspicious: Multiple rare instructions in a row
    if (rare_instruction_count >= 2) {
      confidence -= 0.20f;
      suspicious_pattern_count++;
    }

    // Good: Multiple common instructions in a row
    if (common_instruction_count >= 3) {
      confidence += 0.15f;
    }

    current += inst.bytes.size();
  }

  // Confidence boost based on sequence length (longer = better)
  confidence += (valid_sequence * 0.08f);

  // Penalty for short sequences (might be data that happens to decode)
  if (valid_sequence < 3) {
    confidence -= 0.15f;
  }

  // Check if this address has xrefs (branches pointing to it)
  const auto& xrefs = address_map->GetXrefs(address);
  if (!xrefs.empty()) {
    confidence += 0.25f;  // Strong indicator of valid code target
  }

  // Cap confidence between 0.0 and 1.5 (allow exceeding 1.0 for very strong signals)
  if (confidence < 0.0f) confidence = 0.0f;
  if (confidence > 1.5f) confidence = 1.5f;

  return confidence;
}

bool CodeAnalyzer::ResolveMisalignment(uint32_t target_address,
                                       uint32_t source_address,
                                       bool is_unconditional_branch,
                                       core::AddressMap* address_map) {
  // Find the existing instruction that contains target_address
  uint32_t existing_inst_start = FindPreviousInstructionBoundary(target_address);

  if (existing_inst_start == 0) {
    // Couldn't find existing instruction, allow target
    std::stringstream ss_dbg;
    ss_dbg << std::hex << std::uppercase << "$" << target_address;
    LOG_DEBUG("No existing instruction found containing " + ss_dbg.str() +
              ", allowing branch target");

    // Mark target and surrounding bytes as UNKNOWN to force re-analysis
    // This handles cases where cache was cleared but address_map still has stale CODE markers
    // Use a larger range (32 bytes) to ensure proper re-analysis
    for (uint32_t addr = target_address; addr < target_address + 32 && IsValidAddress(addr); ++addr) {
      if (address_map->GetType(addr) == core::AddressType::CODE) {
        address_map->SetType(addr, core::AddressType::UNKNOWN);
        visited_recursive_.erase(addr);
      }
    }

    // Add to discovered entry points so next pass will analyze from here
    discovered_entry_points_.insert(target_address);
    return true;
  }

  const core::Instruction& existing_inst = instruction_cache_[existing_inst_start];

  std::stringstream ss;
  ss << std::hex << std::uppercase;

  LOG_DEBUG("Misalignment detected:");
  ss.str(""); ss << "$" << source_address;
  std::string src_hex = ss.str();
  ss.str(""); ss << "$" << target_address;
  std::string tgt_hex = ss.str();
  LOG_DEBUG("  Branch from " + src_hex + " to " + tgt_hex);

  ss.str(""); ss << "$" << existing_inst_start;
  LOG_DEBUG("  Conflicts with existing instruction at " + ss.str() + ": " +
            existing_inst.mnemonic + " " + existing_inst.operand);

  // Calculate confidence for both interpretations
  float target_confidence = CalculateInstructionConfidence(target_address, address_map);
  float existing_confidence = CalculateInstructionConfidence(existing_inst_start, address_map);

  // Boost target confidence if it's an unconditional branch/jump
  if (is_unconditional_branch) {
    target_confidence += 0.2f;
    LOG_DEBUG("  Unconditional branch - boosting target confidence");
  }

  // CRITICAL: Check if target starts with PULS/POPS that matches recent PSHS/PSHU
  // This is a VERY strong signal for error handling paths
  const uint8_t* target_data = binary_->GetPointer(target_address);
  if (target_data) {
    uint8_t target_opcode = target_data[0];
    // PULS ($35) or PULU ($37)
    if (target_opcode == 0x35 || target_opcode == 0x37) {
      // Huge boost - stack cleanup after conditional error path is extremely common
      target_confidence += 0.4f;
      LOG_INFO("  Target starts with PULS/PULU (stack cleanup) - strong boost!");
    }
  }

  // Check fallthrough from existing instruction
  uint32_t fallthrough_addr = existing_inst_start + existing_inst.bytes.size();
  float fallthrough_confidence = 0.0f;
  if (IsValidAddress(fallthrough_addr)) {
    fallthrough_confidence = CalculateInstructionConfidence(fallthrough_addr, address_map);
  }

  LOG_INFO("  Confidence scores:");
  ss.str(""); ss << "$" << existing_inst_start;
  LOG_INFO("    Existing instruction at " + ss.str() +
            ": " + std::to_string(existing_confidence));
  ss.str(""); ss << "$" << fallthrough_addr;
  LOG_INFO("    Fallthrough at " + ss.str() +
            ": " + std::to_string(fallthrough_confidence));
  ss.str(""); ss << "$" << target_address;
  LOG_INFO("    Branch target at " + ss.str() +
            ": " + std::to_string(target_confidence));

  // Decision logic:
  // If target confidence significantly higher, invalidate existing and use target
  // If existing confidence higher, keep existing and ignore branch
  // If tied, prefer branch target (tiebreaker: xref existence is evidence)
  const float CONFIDENCE_THRESHOLD = 0.15f;
  const float TIE_MARGIN = 0.05f;  // Within 5% = tied

  bool is_tied = (std::abs(target_confidence - existing_confidence) <= TIE_MARGIN);

  if (target_confidence > existing_confidence + CONFIDENCE_THRESHOLD || is_tied) {
    LOG_INFO("Resolving misalignment: branch target wins (confidence " +
             std::to_string(target_confidence) + " vs " +
             std::to_string(existing_confidence) + ")");
    ss.str(""); ss << "$" << existing_inst_start;
    LOG_INFO("  Invalidating instruction at " + ss.str());

    InvalidateConflictingInstructions(target_address, address_map);

    // CRITICAL: Also invalidate the fallthrough path from the conflicting instruction
    // because it was based on the wrong interpretation
    uint32_t fallthrough_start = existing_inst_start + existing_inst.bytes.size();
    if (fallthrough_start < target_address) {
      // Mark everything from fallthrough to target as UNKNOWN for re-analysis
      for (uint32_t addr = fallthrough_start; addr < target_address; ++addr) {
        address_map->SetType(addr, core::AddressType::UNKNOWN);
        visited_recursive_.erase(addr);  // Allow re-analysis
      }
    }

    // Add to discovered entry points so next pass will analyze from here
    discovered_entry_points_.insert(target_address);

    return true;  // Follow the branch target
  } else {
    LOG_DEBUG("Keeping existing instruction (confidence " +
              std::to_string(existing_confidence) + " vs " +
              std::to_string(target_confidence) + ")");
    return false;  // Keep existing, don't follow branch
  }
}

void CodeAnalyzer::ClearVisitedRange(uint32_t start, uint32_t end) {
  // Remove visited markers for addresses in range
  for (uint32_t addr = start; addr < end; ++addr) {
    visited_recursive_.erase(addr);
  }
}

void CodeAnalyzer::InvalidateConflictingInstructions(uint32_t target_address,
                                                     core::AddressMap* address_map) {
  // Find all instructions that overlap with target_address
  std::vector<uint32_t> to_invalidate;

  for (const auto& pair : instruction_cache_) {
    uint32_t inst_addr = pair.first;
    const core::Instruction& inst = pair.second;
    uint32_t inst_end = inst_addr + inst.bytes.size();

    // Check if this instruction overlaps with target
    if (inst_addr < target_address && target_address < inst_end) {
      to_invalidate.push_back(inst_addr);
    }
  }

  // Remove from cache, mark bytes as UNKNOWN, clear visited markers AND xrefs
  for (uint32_t addr : to_invalidate) {
    const core::Instruction& inst = instruction_cache_[addr];

    std::stringstream ss_inv;
    ss_inv << std::hex << std::uppercase << "$" << addr;
    LOG_DEBUG("Invalidating instruction at " + ss_inv.str() +
              ": " + inst.mnemonic + " " + inst.operand);

    // Mark bytes as DATA (not UNKNOWN) to prevent re-analysis as CODE
    // These bytes were part of an invalid instruction that conflicted with a branch target
    for (size_t i = 0; i < inst.bytes.size(); ++i) {
      uint32_t byte_addr = addr + i;
      address_map->SetType(byte_addr, core::AddressType::DATA);

      // Debug: track $7937
      if (byte_addr == 0x7937) {
        std::cerr << "DEBUG: Marked $7937 as DATA (invalidated from $" << std::hex << addr
                  << ") inst: " << inst.mnemonic << std::dec << std::endl;
      }

      // CRITICAL: Clear visited marker so target address can be re-analyzed
      visited_recursive_.erase(byte_addr);
    }

    // CRITICAL: Remove any xrefs created by this instruction
    // If the instruction is invalid, its branch targets are also invalid
    address_map->RemoveXrefsFrom(addr);

    instruction_cache_.erase(addr);
  }

  // Clear visited marker for target address itself
  visited_recursive_.erase(target_address);
}

bool CodeAnalyzer::DetectAndResolvePostPassMisalignments(core::AddressMap* address_map) {
  // After a complete pass, check all xrefs to see if any point to the middle of instructions
  bool resolved_any = false;

  // Collect all xref targets
  std::set<uint32_t> xref_targets;
  uint32_t start = binary_->load_address();
  uint32_t end = start + binary_->size();

  for (uint32_t addr = start; addr < end; ++addr) {
    const auto& xrefs = address_map->GetXrefs(addr);
    if (!xrefs.empty()) {
      xref_targets.insert(addr);
    }
  }

  // Check each xref target to see if it's in the middle of an instruction
  for (uint32_t target : xref_targets) {
    if (!address_map->IsCode(target)) {
      continue;  // Not in CODE region, skip
    }

    // Check if this is an instruction boundary
    if (IsInstructionBoundary(target)) {
      continue;  // Valid boundary, no problem
    }

    // This xref points into the middle of an instruction - misalignment!
    const auto& xrefs = address_map->GetXrefs(target);
    if (xrefs.empty()) continue;  // Shouldn't happen, but check anyway

    // Get the source of the xref (first one)
    uint32_t source = *xrefs.begin();

    // Check if source is an unconditional branch/jump
    const uint8_t* source_data = binary_->GetPointer(source);
    if (!source_data) continue;

    size_t source_remaining = end - source;
    core::Instruction source_inst;
    try {
      source_inst = cpu_->Disassemble(source_data, source_remaining, source);
    } catch (...) {
      continue;
    }

    bool is_unconditional = (source_inst.mnemonic == "BRA" ||
                             source_inst.mnemonic == "LBRA" ||
                             source_inst.mnemonic == "JMP" ||
                             source_inst.mnemonic == "JSR" ||
                             source_inst.mnemonic == "LBSR");

    std::stringstream ss_post;
    ss_post << std::hex << std::uppercase;
    ss_post << "$" << target;
    std::string target_hex = ss_post.str();
    ss_post.str(""); ss_post << "$" << source;
    std::string source_hex = ss_post.str();
    LOG_INFO("Post-pass misalignment detected at " + target_hex +
             " (xref from " + source_hex + ")");

    // Try to resolve
    if (ResolveMisalignment(target, source, is_unconditional, address_map)) {
      LOG_INFO("  Resolved - will re-analyze");
      resolved_any = true;
    }
  }

  return resolved_any;
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
