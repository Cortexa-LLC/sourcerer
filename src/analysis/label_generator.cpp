// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "analysis/label_generator.h"

#include <iomanip>
#include <sstream>

namespace sourcerer {
namespace analysis {

LabelGenerator::LabelGenerator(core::AddressMap* address_map,
                               const core::Binary* binary,
                               const core::SymbolTable* symbol_table)
    : address_map_(address_map), binary_(binary), symbol_table_(symbol_table) {}

void LabelGenerator::GenerateLabels(const std::vector<core::Instruction>* instructions) {
  if (!address_map_) {
    return;
  }

  // Clear used labels set
  used_labels_.clear();

  // Build subroutine map if instructions provided (for local labels)
  if (instructions) {
    BuildSubroutineMap(instructions);
  }

  // First pass: identify all addresses that need labels
  // These are addresses that are referenced by other instructions
  std::set<uint32_t> addresses_needing_labels;

  // Get all cross-references
  const auto& xrefs = address_map_->GetAllXrefs();
  for (const auto& xref_pair : xrefs) {
    uint32_t target = xref_pair.first;
    addresses_needing_labels.insert(target);
  }

  // Second pass: generate labels for each address
  for (uint32_t address : addresses_needing_labels) {
    // Skip if address already has a label
    if (auto label = address_map_->GetLabel(address)) {
      // Add existing label to used_labels_ to avoid collisions
      used_labels_.insert(*label);
      continue;
    }

    // Check symbol table first (symbols are always valid, even if external)
    if (symbol_table_) {
      if (auto symbol_name = symbol_table_->GetSymbolName(address)) {
        address_map_->SetLabel(address, *symbol_name);
        used_labels_.insert(*symbol_name);
        continue;
      }
    }

    // Only generate labels for addresses within the binary range
    // External addresses without symbols should remain as hex addresses
    if (binary_ && !binary_->IsValidAddress(address)) {
      continue;
    }

    // CRITICAL: Only generate labels for valid instruction/data boundaries
    // Skip addresses in the middle of instructions or data structures
    if (!IsValidLabelAddress(address, instructions)) {
      continue;
    }

    // Check if this is a local branch target (within a subroutine)
    if (!subroutine_map_.empty() && IsLocalBranchTarget(address)) {
      // Generate local label (e.g., .1, .2, .3)
      uint32_t subroutine_start = subroutine_map_[address];
      std::string label = GenerateLocalLabel(address, subroutine_start);
      address_map_->SetLabel(address, label);
      used_labels_.insert(label);
    } else {
      // Generate appropriate full label based on context
      std::string label = GenerateLabelForAddress(address);
      if (!label.empty()) {
        address_map_->SetLabel(address, label);
        used_labels_.insert(label);
      }
    }
  }
}

std::string LabelGenerator::GenerateLabelForAddress(uint32_t address) {
  // Check symbol table first
  if (symbol_table_) {
    if (auto symbol_name = symbol_table_->GetSymbolName(address)) {
      return *symbol_name;
    }
  }

  // Entry point gets special name
  if (IsEntryPoint(address)) {
    return GenerateEntryPointLabel(address);
  }

  // Zero page addresses get special prefix (even if external to binary)
  if (address < 0x100) {
    return GenerateZeroPageLabel(address);
  }

  // ROM addresses (common Apple II ROM ranges)
  // $C000-$CFFF: I/O page
  // $D000-$FFFF: ROM
  if (address >= 0xC000) {
    return GenerateRomLabel(address);
  }

  // Subroutines (JSR targets)
  if (IsSubroutine(address)) {
    return GenerateSubroutineLabel(address);
  }

  // Branch targets
  if (IsBranchTarget(address)) {
    return GenerateBranchLabel(address);
  }

  // Data addresses
  if (address_map_->GetType(address) == core::AddressType::DATA) {
    return GenerateDataLabel(address);
  }

  // Default: generate based on address type
  core::AddressType type = address_map_->GetType(address);
  if (type == core::AddressType::CODE) {
    return GenerateBranchLabel(address);  // Code addresses are branch targets
  } else {
    return GenerateDataLabel(address);
  }
}

std::string LabelGenerator::GenerateEntryPointLabel(uint32_t address) {
  // First entry point gets "MAIN", others get "START_xxxx"
  const auto& entry_points = address_map_->GetEntryPoints();
  if (!entry_points.empty() && address == *entry_points.begin()) {
    return EnsureUnique("MAIN");
  }
  
  std::string base = "START_" + FormatAddressHex(address);
  return EnsureUnique(base);
}

std::string LabelGenerator::GenerateSubroutineLabel(uint32_t address) {
  std::string base = "SUB_" + FormatAddressHex(address);
  return EnsureUnique(base);
}

std::string LabelGenerator::GenerateBranchLabel(uint32_t address) {
  std::string base = "L_" + FormatAddressHex(address);
  return EnsureUnique(base);
}

std::string LabelGenerator::GenerateDataLabel(uint32_t address) {
  std::string base = "DATA_" + FormatAddressHex(address);
  return EnsureUnique(base);
}

std::string LabelGenerator::GenerateZeroPageLabel(uint32_t address) {
  std::ostringstream oss;
  oss << "ZP_" << std::hex << std::uppercase << std::setw(2)
      << std::setfill('0') << address;
  return EnsureUnique(oss.str());
}

std::string LabelGenerator::GenerateRomLabel(uint32_t address) {
  // I/O addresses ($C000-$CFFF) use different prefix
  if (address >= 0xC000 && address < 0xD000) {
    std::ostringstream oss;
    oss << "IO_" << std::hex << std::uppercase << std::setw(4)
        << std::setfill('0') << address;
    return EnsureUnique(oss.str());
  }

  // ROM addresses ($D000-$FFFF)
  std::ostringstream oss;
  oss << "ROM_" << std::hex << std::uppercase << std::setw(4)
      << std::setfill('0') << address;
  return EnsureUnique(oss.str());
}

bool LabelGenerator::IsEntryPoint(uint32_t address) const {
  const auto& entry_points = address_map_->GetEntryPoints();
  return entry_points.find(address) != entry_points.end();
}

bool LabelGenerator::IsSubroutine(uint32_t address) const {
  // An address is a subroutine if it's the target of a JSR instruction
  // We check the xrefs to see if any source instruction is a JSR
  const auto& xrefs = address_map_->GetXrefs(address);
  
  // For now, we'll use a heuristic: if address is referenced and is CODE,
  // and is not just a branch target, it's likely a subroutine
  // This is simplified - ideally we'd check the actual instruction type
  
  if (xrefs.empty()) {
    return false;
  }

  // Check if this address is in CODE region
  if (address_map_->GetType(address) != core::AddressType::CODE) {
    return false;
  }

  // If it has multiple references, likely a subroutine
  // Single references are more likely branch targets
  return xrefs.size() > 1;
}

bool LabelGenerator::IsBranchTarget(uint32_t address) const {
  // An address is a branch target if it has any xrefs and is CODE
  const auto& xrefs = address_map_->GetXrefs(address);
  return !xrefs.empty() && 
         address_map_->GetType(address) == core::AddressType::CODE;
}

std::string LabelGenerator::EnsureUnique(const std::string& base_name) {
  std::string candidate = base_name;
  int suffix = 1;

  while (used_labels_.find(candidate) != used_labels_.end()) {
    std::ostringstream oss;
    oss << base_name << "_" << suffix;
    candidate = oss.str();
    suffix++;
  }

  return candidate;
}

std::string LabelGenerator::FormatAddressHex(uint32_t address,
                                             bool use_dollar_sign) {
  std::ostringstream oss;
  if (use_dollar_sign) {
    oss << "$";
  }
  oss << std::hex << std::uppercase << std::setw(4)
      << std::setfill('0') << address;
  return oss.str();
}

void LabelGenerator::BuildSubroutineMap(const std::vector<core::Instruction>* instructions) {
  if (!instructions || instructions->empty()) {
    return;
  }

  subroutine_map_.clear();
  local_label_counters_.clear();

  uint32_t current_subroutine_start = 0;

  for (const auto& inst : *instructions) {
    // Check if this instruction starts a new subroutine
    // A subroutine starts if:
    // 1. It has a label that indicates it's a subroutine (SUB_xxxx, entry point)
    // 2. It's the target of a JSR instruction
    bool is_subroutine_start = false;

    if (auto label = address_map_->GetLabel(inst.address)) {
      // Check if label indicates a subroutine (not a local label)
      if (label->find("SUB_") == 0 ||
          label->find("MAIN") == 0 ||
          label->find("START") == 0 ||
          label->find("L_") != 0) {  // Not a branch label
        is_subroutine_start = true;
      }
    }

    // Also check if this address is a JSR target
    if (!is_subroutine_start && IsSubroutine(inst.address)) {
      is_subroutine_start = true;
    }

    // Entry points are subroutine starts
    if (!is_subroutine_start && IsEntryPoint(inst.address)) {
      is_subroutine_start = true;
    }

    if (is_subroutine_start) {
      current_subroutine_start = inst.address;
      local_label_counters_[current_subroutine_start] = 0;
    }

    // Map this instruction to its parent subroutine
    if (current_subroutine_start > 0) {
      subroutine_map_[inst.address] = current_subroutine_start;
    }

    // Check for subroutine termination (RTS, RTI, JMP)
    if (inst.is_return || (inst.is_jump && !inst.is_call)) {
      // Next instruction starts a new subroutine (or is unreachable)
      current_subroutine_start = 0;
    }
  }
}

bool LabelGenerator::IsLocalBranchTarget(uint32_t target_address) const {
  // Check if this target has a subroutine mapping
  auto target_it = subroutine_map_.find(target_address);
  if (target_it == subroutine_map_.end()) {
    return false;
  }

  uint32_t target_subroutine = target_it->second;

  // Get all xrefs to this target
  const auto& xrefs = address_map_->GetXrefs(target_address);
  if (xrefs.empty()) {
    return false;
  }

  // Check if ALL xrefs come from the same subroutine
  for (uint32_t source_address : xrefs) {
    auto source_it = subroutine_map_.find(source_address);
    if (source_it == subroutine_map_.end()) {
      // Source not in any subroutine
      return false;
    }

    if (source_it->second != target_subroutine) {
      // Source is in a different subroutine
      return false;
    }
  }

  // All xrefs are from within the same subroutine - it's a local branch
  return true;
}

std::string LabelGenerator::GenerateLocalLabel(uint32_t address, uint32_t subroutine_start) {
  // Increment counter for this subroutine
  int& counter = local_label_counters_[subroutine_start];
  counter++;

  // Generate unique local label using address
  // Format: LOC_XXXX where XXXX is the hex address
  // Using LOC_ instead of @ for vasm compatibility
  std::ostringstream oss;
  oss << "LOC_" << std::hex << std::uppercase << std::setw(4)
      << std::setfill('0') << address;

  return oss.str();
}

bool LabelGenerator::IsValidLabelAddress(uint32_t address, const std::vector<core::Instruction>* instructions) const {
  // Check address type
  core::AddressType type = address_map_->GetType(address);

  // DATA addresses are always valid label targets
  if (type == core::AddressType::DATA) {
    return true;
  }

  // CODE addresses must have an instruction starting at that exact address
  if (type == core::AddressType::CODE) {
    if (!instructions) {
      // No instructions provided - assume valid (conservative)
      return true;
    }

    // Check if there's an instruction starting at this address
    for (const auto& inst : *instructions) {
      if (inst.address == address) {
        return true;  // Valid instruction boundary
      }
      // If this address is in the middle of an instruction, it's invalid
      if (inst.address < address && address < inst.address + inst.bytes.size()) {
        return false;  // Address is in middle of instruction
      }
    }

    // No instruction found at this address - could be orphaned CODE byte
    // Check if it's at least marked as CODE
    return address_map_->IsCode(address);
  }

  // UNKNOWN or other types - allow if zero page or ROM (external symbols)
  if (address < 0x100 || address >= 0xC000) {
    return true;
  }

  // Default: reject UNKNOWN addresses within binary range
  return false;
}

}  // namespace analysis
}  // namespace sourcerer
