// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_ANALYSIS_EQUATE_GENERATOR_H_
#define SOURCERER_ANALYSIS_EQUATE_GENERATOR_H_

#include <map>
#include <string>
#include <vector>

#include "core/equate_provider.h"
#include "core/instruction.h"

namespace sourcerer {
namespace analysis {

/**
 * Concrete implementation of IEquateProvider.
 * Generates equates from instruction analysis by tracking immediate value usage frequency.
 */
class EquateGenerator : public core::IEquateProvider {
 public:
  EquateGenerator() : min_usage_count_(3) {}
  explicit EquateGenerator(int min_usage_count)
      : min_usage_count_(min_usage_count) {}
  ~EquateGenerator() override = default;

  // IEquateProvider interface implementation
  bool HasEquate(uint8_t value) const override;
  std::string GetEquateName(uint8_t value) const override;
  const std::map<uint8_t, std::string>& GetEquates() const override { return equates_; }
  std::string GetEquateComment(uint8_t value) const override;

  // EquateGenerator-specific methods (not in interface)
  void AnalyzeInstructions(const std::vector<core::Instruction>& instructions);
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
