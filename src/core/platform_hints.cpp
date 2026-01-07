// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "core/platform_hints.h"

#include <fstream>
#include <nlohmann/json.hpp>

#include "utils/logger.h"

namespace sourcerer {
namespace core {

using json = nlohmann::json;

PlatformHints::PlatformHints() {}

bool PlatformHints::LoadFromFile(const std::string& path) {
  LOG_INFO("Loading platform hints: " + path);

  std::ifstream file(path);
  if (!file) {
    LOG_ERROR("Failed to open hints file: " + path);
    return false;
  }

  std::string content((std::istreambuf_iterator<char>(file)),
                      std::istreambuf_iterator<char>());
  file.close();

  return LoadFromJson(content);
}

bool PlatformHints::LoadFromJson(const std::string& json_content) {
  try {
    json j = json::parse(json_content);

    // Get platform metadata
    platform_ = j.value("platform", "unknown");
    description_ = j.value("description", "");
    version_ = j.value("version", "1.0");

    LOG_DEBUG("Loading hints for platform: " + platform_);

    // Parse inline_data_routines array
    if (j.contains("inline_data_routines") && j["inline_data_routines"].is_array()) {
      for (const auto& routine : j["inline_data_routines"]) {
        InlineDataRoutine info;

        // Parse address (support hex string or integer)
        if (routine["address"].is_string()) {
          std::string addr_str = routine["address"];
          if (addr_str.substr(0, 2) == "0x" || addr_str.substr(0, 1) == "$") {
            // Remove $ prefix if present
            if (addr_str[0] == '$') {
              addr_str = "0x" + addr_str.substr(1);
            }
            info.address = std::stoul(addr_str, nullptr, 16);
          } else {
            info.address = std::stoul(addr_str, nullptr, 0);
          }
        } else {
          info.address = routine["address"];
        }

        info.name = routine.value("name", "");
        info.description = routine.value("description", "");
        info.pattern = routine.value("pattern", "");
        info.bytes_after_call = routine.value("bytes_after_call", 0);

        inline_data_routines_[info.address] = info;

        LOG_DEBUG("Registered inline data routine: " + info.name +
                  " at $" + std::to_string(info.address) +
                  " (" + std::to_string(info.bytes_after_call) + " bytes)");
      }
    }

    // Parse mli_parameter_structures object
    if (j.contains("mli_parameter_structures") && j["mli_parameter_structures"].is_object()) {
      for (auto& [key, value] : j["mli_parameter_structures"].items()) {
        // Parse call number from hex string
        uint32_t call_num = 0;
        if (key.substr(0, 2) == "0x" || key.substr(0, 1) == "$") {
          std::string num_str = key;
          if (num_str[0] == '$') {
            num_str = "0x" + num_str.substr(1);
          }
          call_num = std::stoul(num_str, nullptr, 16);
        } else {
          call_num = std::stoul(key, nullptr, 0);
        }

        MliCallInfo call_info;
        call_info.name = value.value("name", "");
        call_info.description = value.value("description", "");

        // Parse parameters array if present
        if (value.contains("parameters") && value["parameters"].is_array()) {
          for (const auto& param : value["parameters"]) {
            MliParameter p;
            p.offset = param.value("offset", 0);
            p.size = param.value("size", 0);
            p.name = param.value("name", "");
            p.description = param.value("description", "");
            call_info.parameters.push_back(p);
          }
          LOG_DEBUG("  Loaded " + std::to_string(call_info.parameters.size()) +
                    " parameters for " + call_info.name);
        }

        mli_call_info_[call_num] = call_info;

        LOG_DEBUG("Registered MLI call: $" + std::to_string(call_num) +
                  " = " + call_info.name);
      }
    }

    LOG_INFO("Loaded " + std::to_string(inline_data_routines_.size()) +
             " inline data routines and " + std::to_string(mli_call_info_.size()) +
             " MLI call structures");

    return true;

  } catch (const json::exception& e) {
    LOG_ERROR("JSON parse error: " + std::string(e.what()));
    return false;
  } catch (const std::exception& e) {
    LOG_ERROR("Error loading hints: " + std::string(e.what()));
    return false;
  }
}

bool PlatformHints::IsInlineDataRoutine(uint32_t address,
                                        size_t* bytes_after_call) const {
  auto it = inline_data_routines_.find(address);
  if (it != inline_data_routines_.end()) {
    if (bytes_after_call) {
      *bytes_after_call = it->second.bytes_after_call;
    }
    return true;
  }
  return false;
}

std::optional<MliCallInfo> PlatformHints::GetMliCallInfo(uint32_t call_number) const {
  auto it = mli_call_info_.find(call_number);
  if (it != mli_call_info_.end()) {
    return it->second;
  }
  return std::nullopt;
}

void PlatformHints::Clear() {
  platform_.clear();
  description_.clear();
  version_.clear();
  inline_data_routines_.clear();
  mli_call_info_.clear();
}

}  // namespace core
}  // namespace sourcerer
