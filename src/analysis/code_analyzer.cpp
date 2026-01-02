// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "analysis/code_analyzer.h"

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

  // Analyze using queue-based algorithm
  AnalyzeFromQueue(address_map);

  // Mark remaining bytes as data
  uint32_t start = binary_->load_address();
  uint32_t end = start + binary_->size();
  
  for (uint32_t addr = start; addr < end; ++addr) {
    if (address_map->GetType(addr) == core::AddressType::UNKNOWN) {
      address_map->SetType(addr, core::AddressType::DATA);
      data_bytes_++;
    }
  }

  LOG_INFO("Code flow analysis complete");
  LOG_INFO("  Instructions: " + std::to_string(instruction_count_));
  LOG_INFO("  Code bytes: " + std::to_string(code_bytes_));
  LOG_INFO("  Data bytes: " + std::to_string(data_bytes_));

  // Second pass: Reclassify CODE regions that look like data
  LOG_INFO("Running second pass: data region detection...");
  ReclassifyDataRegions(address_map);
  LOG_INFO("Second pass complete");
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

bool CodeAnalyzer::ShouldStopPath(const core::Instruction& inst) const {
  // Stop on returns (RTS, RTI)
  if (inst.is_return) {
    return true;
  }

  // Stop on unconditional jumps (JMP absolute)
  // But NOT on conditional branches (BEQ, BNE, etc.)
  if (inst.is_jump && !inst.is_branch) {
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

void CodeAnalyzer::ReclassifyDataRegions(core::AddressMap* address_map) {
  // Find contiguous CODE regions and scan for suspicious sub-regions
  uint32_t start = binary_->load_address();
  uint32_t end = start + binary_->size();

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
    // (e.g., inline data from JSR to MLI or other inline data routines)
    bool contains_explicit_data = false;
    for (uint32_t check_addr = code_block_start; check_addr < code_block_end; ++check_addr) {
      core::AddressType type = address_map->GetType(check_addr);
      if (type == core::AddressType::DATA || type == core::AddressType::INLINE_DATA) {
        contains_explicit_data = true;
        break;
      }
    }

    // If this CODE block contains explicit DATA markers, skip it entirely
    // Those DATA markers were intentionally placed during code flow analysis
    if (contains_explicit_data) {
      LOG_DEBUG("Skipping CODE block $" + std::to_string(code_block_start) +
                "-$" + std::to_string(code_block_end - 1) +
                " (contains explicit DATA markers from inline data detection)");
      addr = code_block_end;
      continue;
    }

    // No explicit DATA markers - proceed with heuristic analysis
    // Use a sliding window approach
    const uint32_t window_size = 16;  // Check 16-byte windows

    addr = code_block_start;
    while (addr < code_block_end) {
      // Check if this looks like the start of a data region
      uint32_t window_end = std::min(addr + window_size, code_block_end);

      // For regions at least 16 bytes, check if they look like data
      if (window_end - addr >= window_size) {
        // Check this window and potentially extend it
        if (LooksLikeData(addr, window_end - 1)) {
          // Found a suspicious region - extend it to find the full data block
          uint32_t data_end = window_end;
          while (data_end < code_block_end && address_map->IsCode(data_end) &&
                 LooksLikeData(addr, data_end)) {
            data_end++;
          }

          // Only reclassify if:
          // 1. Region doesn't contain entry points
          // 2. Region is at least 16 bytes
          bool contains_entry_point = false;
          for (uint32_t ep : entry_points_) {
            if (ep >= addr && ep < data_end) {
              contains_entry_point = true;
              break;
            }
          }

          if (!contains_entry_point && (data_end - addr) >= 16) {
            LOG_DEBUG("Reclassifying CODE region $" + std::to_string(addr) +
                      "-$" + std::to_string(data_end - 1) + " as DATA");

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
  int address_like_pairs = 0;
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

}  // namespace analysis
}  // namespace sourcerer
