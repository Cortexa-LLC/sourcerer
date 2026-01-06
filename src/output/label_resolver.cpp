// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "output/label_resolver.h"

#include <iomanip>
#include <regex>
#include <sstream>

namespace sourcerer {
namespace output {

uint32_t LabelResolver::ExtractAddressFromOperand(const std::string& operand) {
  // Use regex to find hex addresses in various formats
  std::regex hex_regex(R"(\$([0-9A-Fa-f]+))");
  std::smatch match;

  if (std::regex_search(operand, match, hex_regex)) {
    try {
      return std::stoul(match[1].str(), nullptr, 16);
    } catch (...) {
      return 0xFFFFFFFF;
    }
  }

  return 0xFFFFFFFF;
}

std::string LabelResolver::ReplaceAddressInOperand(
    const std::string& operand,
    uint32_t address,
    const std::string& replacement) {

  // Build address strings to try (both 2-digit and 4-digit formats)
  std::ostringstream addr_str_4;
  addr_str_4 << "$" << std::hex << std::uppercase << std::setw(4)
             << std::setfill('0') << address;

  std::ostringstream addr_str_2;
  addr_str_2 << "$" << std::hex << std::uppercase << std::setw(2)
             << std::setfill('0') << address;

  std::string result = operand;

  // Try 4-digit format first (more specific)
  size_t pos = result.find(addr_str_4.str());
  if (pos != std::string::npos) {
    result.replace(pos, addr_str_4.str().length(), replacement);
    return result;
  }

  // Try 2-digit format
  pos = result.find(addr_str_2.str());
  if (pos != std::string::npos) {
    result.replace(pos, addr_str_2.str().length(), replacement);
    return result;
  }

  return result;
}

LabelSubstitutionResult LabelResolver::SubstituteLabel(const std::string& operand) const {
  LabelSubstitutionResult result;
  result.operand = operand;
  result.substituted = false;
  result.extracted_address = ExtractAddressFromOperand(operand);

  if (result.extracted_address == 0xFFFFFFFF) {
    return result;  // No address found
  }

  uint32_t addr = result.extracted_address;

  // Priority 1: Try symbol table first (explicit user-provided symbols)
  if (symbol_table_) {
    if (auto symbol_name = symbol_table_->GetSymbolName(addr)) {
      result.operand = ReplaceAddressInOperand(result.operand, addr, *symbol_name);
      result.substituted = true;
      return result;
    }
  }

  // Priority 2: Check address map for generated labels
  // Only substitute if the address has an instruction or is at a valid boundary
  if (address_map_) {
    if (auto label = address_map_->GetLabel(addr)) {
      if (address_map_->IsCode(addr) || address_map_->IsData(addr)) {
        result.operand = ReplaceAddressInOperand(result.operand, addr, *label);
        result.substituted = true;
      }
    }
  }

  return result;
}

}  // namespace output
}  // namespace sourcerer
