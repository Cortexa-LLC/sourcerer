// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "analysis/hints_parser.h"

#include <fstream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace sourcerer {
namespace analysis {

bool HintsParser::ParseFile(const std::string& file_path, Hints* hints,
                            std::string* error) {
  // Read file
  std::ifstream file(file_path);
  if (!file.is_open()) {
    *error = "Failed to open hints file: " + file_path;
    return false;
  }

  std::string json_content((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());
  file.close();

  return ParseJson(json_content, hints, error);
}

bool HintsParser::ParseJson(const std::string& json_content, Hints* hints,
                            std::string* error) {
  try {
    json j = json::parse(json_content);

    // Parse entry points
    if (j.contains("entry_points") && j["entry_points"].is_array()) {
      for (const auto& entry : j["entry_points"]) {
        uint32_t address;
        if (ParseAddress(entry.get<std::string>(), &address, error)) {
          hints->entry_points.push_back(address);
        } else {
          *error = "Invalid entry point address: " + entry.get<std::string>();
          return false;
        }
      }
    }

    // Parse code regions
    if (j.contains("code_regions") && j["code_regions"].is_array()) {
      for (const auto& region : j["code_regions"]) {
        if (!region.contains("start") || !region.contains("end")) {
          *error = "Code region missing 'start' or 'end' field";
          return false;
        }

        RegionHint hint;
        if (!ParseAddress(region["start"].get<std::string>(), 
                         &hint.start_address, error)) {
          return false;
        }
        if (!ParseAddress(region["end"].get<std::string>(), 
                         &hint.end_address, error)) {
          return false;
        }
        hint.type = core::AddressType::HINT_CODE;
        hints->code_regions.push_back(hint);
      }
    }

    // Parse data regions
    if (j.contains("data_regions") && j["data_regions"].is_array()) {
      for (const auto& region : j["data_regions"]) {
        if (!region.contains("start") || !region.contains("end")) {
          *error = "Data region missing 'start' or 'end' field";
          return false;
        }

        RegionHint hint;
        if (!ParseAddress(region["start"].get<std::string>(), 
                         &hint.start_address, error)) {
          return false;
        }
        if (!ParseAddress(region["end"].get<std::string>(), 
                         &hint.end_address, error)) {
          return false;
        }
        hint.type = core::AddressType::HINT_DATA;
        hints->data_regions.push_back(hint);
      }
    }

    // Parse labels
    if (j.contains("labels") && j["labels"].is_object()) {
      for (auto& [addr_str, label] : j["labels"].items()) {
        uint32_t address;
        if (ParseAddress(addr_str, &address, error)) {
          hints->labels[address] = label.get<std::string>();
        } else {
          *error = "Invalid label address: " + addr_str;
          return false;
        }
      }
    }

    // Parse comments
    if (j.contains("comments") && j["comments"].is_object()) {
      for (auto& [addr_str, comment] : j["comments"].items()) {
        uint32_t address;
        if (ParseAddress(addr_str, &address, error)) {
          hints->comments[address] = comment.get<std::string>();
        } else {
          *error = "Invalid comment address: " + addr_str;
          return false;
        }
      }
    }

    return true;

  } catch (const json::exception& e) {
    *error = std::string("JSON parse error: ") + e.what();
    return false;
  }
}

void HintsParser::ApplyHints(const Hints& hints, core::AddressMap* address_map) {
  if (!address_map) {
    return;
  }

  // Apply entry points
  for (uint32_t entry : hints.entry_points) {
    address_map->AddEntryPoint(entry);
  }

  // Apply code regions
  for (const auto& region : hints.code_regions) {
    for (uint32_t addr = region.start_address; 
         addr <= region.end_address; ++addr) {
      address_map->SetType(addr, region.type);
    }
  }

  // Apply data regions
  for (const auto& region : hints.data_regions) {
    for (uint32_t addr = region.start_address; 
         addr <= region.end_address; ++addr) {
      address_map->SetType(addr, region.type);
    }
  }

  // Apply labels
  for (const auto& [address, label] : hints.labels) {
    address_map->SetLabel(address, label);
  }

  // Apply comments
  for (const auto& [address, comment] : hints.comments) {
    address_map->SetComment(address, comment);
  }
}

bool HintsParser::ParseAddress(const std::string& addr_str, uint32_t* address,
                               std::string* error) {
  try {
    // Check for hex prefix (0x or $)
    if (addr_str.size() >= 2) {
      if (addr_str[0] == '0' && (addr_str[1] == 'x' || addr_str[1] == 'X')) {
        // 0x prefix
        *address = std::stoul(addr_str.substr(2), nullptr, 16);
        return true;
      } else if (addr_str[0] == '$') {
        // $ prefix
        *address = std::stoul(addr_str.substr(1), nullptr, 16);
        return true;
      }
    }

    // Try decimal
    *address = std::stoul(addr_str, nullptr, 10);
    return true;

  } catch (const std::exception& e) {
    *error = std::string("Invalid address format: ") + addr_str;
    return false;
  }
}

}  // namespace analysis
}  // namespace sourcerer
