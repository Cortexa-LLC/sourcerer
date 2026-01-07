// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "analysis/strategies/jump_table_detector.h"

#include <algorithm>

#include "utils/logger.h"

namespace sourcerer {
namespace analysis {

JumpTableDetector::JumpTableDetector(cpu::CpuPlugin* cpu,
                                     const core::Binary* binary)
    : cpu_(cpu), binary_(binary) {}

bool JumpTableDetector::IsValidAddress(uint32_t address) const {
  uint32_t start = binary_->load_address();
  uint32_t end = start + binary_->size();
  return address >= start && address < end;
}

bool JumpTableDetector::IsLikelyCode(uint32_t address, size_t scan_length) const {
  if (!IsValidAddress(address)) return false;

  // Delegate to CPU plugin (SOLID architecture)
  const uint8_t* data = binary_->GetPointer(address);
  size_t remaining = binary_->load_address() + binary_->size() - address;

  return cpu_->IsLikelyCode(data, remaining, address, scan_length);
}

bool JumpTableDetector::IsLikelyCodePointer(uint16_t address) const {
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

std::vector<JumpTableDetector::JumpTableCandidate>
JumpTableDetector::FindJumpTableCandidates(core::AddressMap* address_map) const {
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
    while (current < end - 1 && targets.size() < kMaxJumpTableEntries) {
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
    if (targets.size() >= kMinJumpTableEntries) {
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

float JumpTableDetector::CalculateTableConfidence(
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

bool JumpTableDetector::ValidateJumpTable(const JumpTableCandidate& candidate,
                                         core::AddressMap* address_map) const {
  // Check confidence threshold
  if (candidate.confidence < kMinConfidence) {
    return false;
  }

  // Check entry count range
  size_t entry_count = candidate.GetEntryCount();
  if (entry_count < kMinJumpTableEntries ||
      entry_count > kMaxJumpTableEntries) {
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

void JumpTableDetector::ProcessJumpTable(const JumpTableCandidate& table,
                                        core::AddressMap* address_map,
                                        std::set<uint32_t>* discovered_entry_points) {
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
      discovered_entry_points->insert(target);
      address_map->AddXref(target, table.start_address);
    }
  }

  LOG_INFO("Jump table at $" + std::to_string(table.start_address) +
           ": " + std::to_string(table.GetEntryCount()) + " entries, " +
           "confidence " + std::to_string(table.confidence));
}

void JumpTableDetector::ScanForJumpTables(core::AddressMap* address_map,
                                          std::set<uint32_t>* discovered_entry_points) {
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
      ProcessJumpTable(candidate, address_map, discovered_entry_points);
      processed_count++;
    } else {
      LOG_DEBUG("Rejected jump table candidate at $" +
                std::to_string(candidate.start_address) +
                " (confidence: " + std::to_string(candidate.confidence) + ")");
    }
  }

  LOG_INFO("Processed " + std::to_string(processed_count) + " jump table(s)");
}

}  // namespace analysis
}  // namespace sourcerer
