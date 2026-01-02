// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_ANALYSIS_HINTS_PARSER_H_
#define SOURCERER_ANALYSIS_HINTS_PARSER_H_

#include <cstdint>
#include <string>
#include <vector>

#include "core/address_map.h"

namespace sourcerer {
namespace analysis {

// Region hint specifying address range and type
struct RegionHint {
  uint32_t start_address;
  uint32_t end_address;
  core::AddressType type;
};

// Parsed hints from JSON file
struct Hints {
  std::vector<uint32_t> entry_points;
  std::vector<RegionHint> code_regions;
  std::vector<RegionHint> data_regions;
  std::map<uint32_t, std::string> labels;
  std::map<uint32_t, std::string> comments;
};

// Parses hint files to guide disassembly
class HintsParser {
 public:
  HintsParser() = default;

  // Parse hints from JSON file
  // Returns true on success, false on error
  bool ParseFile(const std::string& file_path, Hints* hints, 
                 std::string* error);

  // Parse hints from JSON string
  bool ParseJson(const std::string& json_content, Hints* hints,
                 std::string* error);

  // Apply hints to address map
  // This sets entry points, marks code/data regions, and adds labels/comments
  static void ApplyHints(const Hints& hints, core::AddressMap* address_map);

 private:
  // Helper: Parse address from JSON value (supports hex and decimal)
  static bool ParseAddress(const std::string& addr_str, uint32_t* address,
                          std::string* error);
};

}  // namespace analysis
}  // namespace sourcerer

#endif  // SOURCERER_ANALYSIS_HINTS_PARSER_H_
