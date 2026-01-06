// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_OUTPUT_LABEL_RESOLVER_H_
#define SOURCERER_OUTPUT_LABEL_RESOLVER_H_

#include <cstdint>
#include <string>

#include "core/address_map.h"
#include "core/symbol_table.h"

namespace sourcerer {
namespace output {

// Label substitution result
struct LabelSubstitutionResult {
  std::string operand;
  bool substituted;
  uint32_t extracted_address;  // 0xFFFFFFFF if none extracted
};

// Component responsible for resolving labels and symbols
// Handles label substitution and address extraction from operands
class LabelResolver {
 public:
  LabelResolver(const core::AddressMap* address_map,
                const core::SymbolTable* symbol_table)
      : address_map_(address_map), symbol_table_(symbol_table) {}

  // Extract address from operand string
  // Handles formats like "$C000", "#$FF", "($FDED)", "($40),Y"
  static uint32_t ExtractAddressFromOperand(const std::string& operand);

  // Substitute label in operand if address has label
  // Validates that address is at valid instruction/data boundary
  // Priority: symbol_table first, then address_map
  LabelSubstitutionResult SubstituteLabel(const std::string& operand) const;

  // Helper: Replace hex address in operand with symbol/label name
  static std::string ReplaceAddressInOperand(
      const std::string& operand,
      uint32_t address,
      const std::string& replacement);

 private:
  const core::AddressMap* address_map_;
  const core::SymbolTable* symbol_table_;
};

}  // namespace output
}  // namespace sourcerer

#endif  // SOURCERER_OUTPUT_LABEL_RESOLVER_H_
