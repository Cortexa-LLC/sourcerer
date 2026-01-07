// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_CORE_PLATFORM_HINTS_H_
#define SOURCERER_CORE_PLATFORM_HINTS_H_

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace sourcerer {
namespace core {

// Inline data routine hint
struct InlineDataRoutine {
  uint32_t address;
  std::string name;
  std::string description;
  std::string pattern;
  size_t bytes_after_call;
};

// MLI parameter definition
struct MliParameter {
  int offset;             // Offset in parameter block
  int size;               // Size in bytes
  std::string name;       // Parameter name
  std::string description;  // Parameter description
};

// MLI parameter structure info
struct MliCallInfo {
  std::string name;
  std::string description;
  std::vector<MliParameter> parameters;  // Parameter structure details
};

// Platform-specific hints for analysis
class PlatformHints {
 public:
  PlatformHints();

  // Load hints from JSON file
  bool LoadFromFile(const std::string& path);

  // Load hints from JSON string
  bool LoadFromJson(const std::string& json_content);

  // Query inline data routines
  bool IsInlineDataRoutine(uint32_t address, size_t* bytes_after_call = nullptr) const;

  // Query MLI call information
  std::optional<MliCallInfo> GetMliCallInfo(uint32_t call_number) const;

  // Get platform name
  std::string GetPlatform() const { return platform_; }

  // Clear all hints
  void Clear();

 private:
  std::string platform_;
  std::string description_;
  std::string version_;

  // Inline data routines (address -> routine info)
  std::map<uint32_t, InlineDataRoutine> inline_data_routines_;

  // MLI parameter structures (call_number -> info)
  std::map<uint32_t, MliCallInfo> mli_call_info_;
};

}  // namespace core
}  // namespace sourcerer

#endif  // SOURCERER_CORE_PLATFORM_HINTS_H_
