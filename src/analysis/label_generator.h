// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_ANALYSIS_LABEL_GENERATOR_H_
#define SOURCERER_ANALYSIS_LABEL_GENERATOR_H_

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "core/address_map.h"
#include "core/binary.h"
#include "core/instruction.h"
#include "core/symbol_table.h"

namespace sourcerer {
namespace analysis {

// Generates meaningful labels for addresses in disassembly
class LabelGenerator {
 public:
  LabelGenerator(core::AddressMap* address_map,
                 const core::Binary* binary = nullptr,
                 const core::SymbolTable* symbol_table = nullptr);

  // Generate labels for all addresses that need them
  // This analyzes the address map and creates appropriate labels
  // If instructions are provided, local labels will be generated for branch targets
  void GenerateLabels(const std::vector<core::Instruction>* instructions = nullptr);

  // Generate a single label for a specific address
  // Returns the generated label, or empty string if address already has label
  std::string GenerateLabelForAddress(uint32_t address);

 private:
  core::AddressMap* address_map_;
  const core::Binary* binary_;
  const core::SymbolTable* symbol_table_;
  std::set<std::string> used_labels_;  // Track label name collisions

  // Label generation strategies
  std::string GenerateEntryPointLabel(uint32_t address);
  std::string GenerateSubroutineLabel(uint32_t address);
  std::string GenerateBranchLabel(uint32_t address);
  std::string GenerateDataLabel(uint32_t address);
  std::string GenerateZeroPageLabel(uint32_t address);
  std::string GenerateRomLabel(uint32_t address);

  // Check if address is an entry point
  bool IsEntryPoint(uint32_t address) const;

  // Check if address is a subroutine (target of JSR)
  bool IsSubroutine(uint32_t address) const;

  // Check if address is a branch target (target of branch instruction)
  bool IsBranchTarget(uint32_t address) const;

  // Build map of address -> parent subroutine start address
  void BuildSubroutineMap(const std::vector<core::Instruction>* instructions);

  // Check if a branch target is local to a subroutine
  bool IsLocalBranchTarget(uint32_t target_address) const;

  // Generate local label name (formatter-specific)
  std::string GenerateLocalLabel(uint32_t address, uint32_t subroutine_start);

  // Ensure label name is unique
  std::string EnsureUnique(const std::string& base_name);

  // Format address as hex string
  std::string FormatAddressHex(uint32_t address, bool use_dollar_sign = false);

  // Map of address -> parent subroutine start address
  std::map<uint32_t, uint32_t> subroutine_map_;

  // Local label counters per subroutine
  std::map<uint32_t, int> local_label_counters_;
};

}  // namespace analysis
}  // namespace sourcerer

#endif  // SOURCERER_ANALYSIS_LABEL_GENERATOR_H_
