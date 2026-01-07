// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "analysis/strategies/code_flow_strategy.h"

#include "analysis/strategies/entry_point_discovery_strategy.h"
#include "analysis/strategies/inline_data_scanner.h"
#include "analysis/strategies/misalignment_resolver.h"
#include "core/constants.h"
#include "utils/logger.h"

namespace sourcerer {
namespace analysis {

CodeFlowStrategy::CodeFlowStrategy(
    cpu::CpuPlugin* cpu,
    const core::Binary* binary,
    MisalignmentResolver* misalignment_resolver,
    EntryPointDiscoveryStrategy* entry_point_discovery,
    InlineDataScanner* inline_data_scanner)
    : cpu_(cpu),
      binary_(binary),
      misalignment_resolver_(misalignment_resolver),
      entry_point_discovery_(entry_point_discovery),
      inline_data_scanner_(inline_data_scanner) {}

bool CodeFlowStrategy::IsValidAddress(uint32_t address) const {
  uint32_t start = binary_->load_address();
  uint32_t end = start + binary_->size();
  return address >= start && address < end;
}

void CodeFlowStrategy::ClearVisited() {
  visited_recursive_.clear();
}

bool CodeFlowStrategy::WasVisited(uint32_t address) const {
  return visited_recursive_.count(address) > 0;
}

void CodeFlowStrategy::AnalyzeRecursively(
    uint32_t address,
    core::AddressMap* address_map,
    std::map<uint32_t, core::Instruction>* instruction_cache,
    std::set<uint32_t>* lea_targets,
    int* code_bytes_discovered,
    size_t* instruction_count,
    int depth) {
  // Prevent infinite recursion
  if (depth > constants::kMaxRecursionDepth) {
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
    } catch (const std::exception& e) {
      LOG_DEBUG("Disassembly failed at $" + std::to_string(current) +
                ": " + e.what());
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
        (*code_bytes_discovered)++;
      }
    }

    // Cache instruction at this boundary
    (*instruction_cache)[current] = inst;

    // Count instruction if it's new
    if (is_new_instruction) {
      (*instruction_count)++;
    }

    // Track LEA/LEAX/LEAY targets (potential data pointers)
    if (inst.mnemonic == "LEAX" || inst.mnemonic == "LEAY" ||
        inst.mnemonic == "LEAU" || inst.mnemonic == "LEAS") {
      if (inst.target_address != 0) {
        lea_targets->insert(inst.target_address);
        entry_point_discovery_->RecordLeaTarget(inst.target_address);
      }
    }

    // Handle branches - RECURSIVELY explore both paths
    if (inst.is_branch) {
      if (inst.target_address != 0) {
        // Add cross-reference
        address_map->AddXref(inst.target_address, current);

        // Check for misalignment
        bool should_follow = true;
        if (misalignment_resolver_->DetectMisalignment(inst.target_address, address_map)) {
          // Check if this is an unconditional branch (BRA, LBRA)
          bool is_unconditional = (inst.mnemonic == "BRA" || inst.mnemonic == "LBRA");

          // Resolve the conflict
          std::set<uint32_t> temp_discovered;
          should_follow = misalignment_resolver_->ResolveMisalignment(
              inst.target_address, current, is_unconditional, address_map,
              &temp_discovered, &visited_recursive_);
        }

        // RECURSIVE: Follow branch target if resolved or no conflict
        if (should_follow) {
          AnalyzeRecursively(inst.target_address, address_map, instruction_cache,
                           lea_targets, code_bytes_discovered, instruction_count,
                           depth + 1);
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
        if (misalignment_resolver_->DetectMisalignment(inst.target_address, address_map)) {
          // Jumps are unconditional
          std::set<uint32_t> temp_discovered;
          should_follow = misalignment_resolver_->ResolveMisalignment(
              inst.target_address, current, true, address_map,
              &temp_discovered, &visited_recursive_);
        }

        // RECURSIVE: Follow jump target if resolved or no conflict
        if (should_follow) {
          AnalyzeRecursively(inst.target_address, address_map, instruction_cache,
                           lea_targets, code_bytes_discovered, instruction_count,
                           depth + 1);
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
        if (misalignment_resolver_->DetectMisalignment(inst.target_address, address_map)) {
          // JSR is unconditional
          std::set<uint32_t> temp_discovered;
          should_follow = misalignment_resolver_->ResolveMisalignment(
              inst.target_address, current, true, address_map,
              &temp_discovered, &visited_recursive_);
        }

        // RECURSIVE: Analyze subroutine if resolved or no conflict
        if (should_follow) {
          AnalyzeRecursively(inst.target_address, address_map, instruction_cache,
                           lea_targets, code_bytes_discovered, instruction_count,
                           depth + 1);
        }
      }

      // Check for inline data after call (e.g., ProDOS MLI)
      size_t inline_bytes = 0;
      if (inline_data_scanner_ &&
          inline_data_scanner_->IsKnownRoutine(inst.target_address, &inline_bytes)) {
        // Mark next N bytes as INLINE_DATA
        uint32_t inline_addr = current + inst.bytes.size();
        for (size_t i = 0; i < inline_bytes && IsValidAddress(inline_addr + i); ++i) {
          address_map->SetType(inline_addr + i, core::AddressType::INLINE_DATA);
          (*code_bytes_discovered)++;
        }
        LOG_DEBUG("Marked " + std::to_string(inline_bytes) +
                  " inline data bytes after JSR at $" + std::to_string(current));
        // Continue after call AND inline data
        current += inst.bytes.size() + inline_bytes;
        continue;
      }

      // Continue after call (no inline data)
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

int CodeFlowStrategy::RunAnalysisPass(
    core::AddressMap* address_map,
    const std::set<uint32_t>& entry_points,
    const std::set<uint32_t>& discovered_entry_points,
    std::map<uint32_t, core::Instruction>* instruction_cache,
    std::set<uint32_t>* lea_targets,
    int* code_bytes_discovered,
    size_t* instruction_count,
    int passes_completed) {
  int initial_bytes = *code_bytes_discovered;

  // Clear visited set for new pass (but keep instruction cache for post-pass detection)
  visited_recursive_.clear();

  // Analyze from all known entry points
  for (uint32_t ep : entry_points) {
    AnalyzeRecursively(ep, address_map, instruction_cache, lea_targets,
                      code_bytes_discovered, instruction_count, 0);
  }

  // Also analyze from newly discovered entry points
  for (uint32_t ep : discovered_entry_points) {
    AnalyzeRecursively(ep, address_map, instruction_cache, lea_targets,
                      code_bytes_discovered, instruction_count, 0);
  }

  int bytes_this_pass = *code_bytes_discovered - initial_bytes;
  LOG_INFO("Pass " + std::to_string(passes_completed) +
           " discovered " + std::to_string(bytes_this_pass) + " bytes");

  // Post-pass: detect and resolve misalignments (needs instruction_cache_)
  LOG_DEBUG("Running post-pass misalignment detection...");
  std::set<uint32_t> temp_discovered;
  bool resolved_misalignments = misalignment_resolver_->DetectAndResolvePostPassMisalignments(
      address_map, &temp_discovered, &visited_recursive_);

  // NOW clear instruction cache for next pass
  instruction_cache->clear();

  if (resolved_misalignments) {
    LOG_INFO("Post-pass resolved conflicts, forcing re-analysis");
    // Return non-zero to force another pass
    return 1;
  }

  return bytes_this_pass;
}

}  // namespace analysis
}  // namespace sourcerer
