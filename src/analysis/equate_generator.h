// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_ANALYSIS_EQUATE_GENERATOR_H_
#define SOURCERER_ANALYSIS_EQUATE_GENERATOR_H_

#include <map>
#include <string>
#include <vector>

#include "core/instruction.h"

namespace sourcerer {
namespace analysis {

// Generates equates (named constants) for commonly used immediate values
class EquateGenerator {
 public:
  EquateGenerator() : min_usage_count_(3) {}
  explicit EquateGenerator(int min_usage_count)
      : min_usage_count_(min_usage_count) {}

  // Analyze instructions to find commonly used immediate values
  void AnalyzeInstructions(const std::vector<core::Instruction>& instructions);

  // Check if a value has an equate
  bool HasEquate(uint8_t value) const;

  // Get equate name for a value
  std::string GetEquateName(uint8_t value) const;

  // Get all equates (value -> name mapping)
  const std::map<uint8_t, std::string>& GetEquates() const { return equates_; }

  // Get equate comment for a value
  std::string GetEquateComment(uint8_t value) const;

  // Get usage count for a value
  int GetUsageCount(uint8_t value) const;

 private:
  // Generate a name for a value based on its usage patterns
  std::string GenerateEquateName(uint8_t value, int usage_count) const;

  int min_usage_count_;  // Minimum times a value must be used to get an equate
  std::map<uint8_t, int> value_counts_;  // Track usage frequency
  std::map<uint8_t, std::string> equates_;  // value -> equate name
  std::map<uint8_t, std::string> equate_comments_;  // value -> comment
};

}  // namespace analysis
}  // namespace sourcerer

#endif  // SOURCERER_ANALYSIS_EQUATE_GENERATOR_H_
