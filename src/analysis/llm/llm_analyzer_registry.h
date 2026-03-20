// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_ANALYSIS_LLM_LLM_ANALYZER_REGISTRY_H_
#define SOURCERER_ANALYSIS_LLM_LLM_ANALYZER_REGISTRY_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "analysis/llm/llm_analyzer.h"

namespace sourcerer {
namespace analysis {
namespace llm {

// Registry for LLM analyzer plugins. Follows the same singleton pattern as
// FormatterRegistry and CpuRegistry.
class LlmAnalyzerRegistry {
 public:
  static LlmAnalyzerRegistry& Instance();

  // Register an analyzer factory under the given name.
  void Register(const std::string& name, LlmAnalyzerFactory factory);

  // Create an analyzer by name. Returns nullptr if not found.
  std::unique_ptr<LlmAnalyzer> Create(const std::string& name) const;

  // Return list of registered provider names.
  std::vector<std::string> ListProviders() const;

  // Returns true if the given name is registered.
  bool Has(const std::string& name) const;

 private:
  LlmAnalyzerRegistry();
  void RegisterBuiltinProviders();

  std::map<std::string, LlmAnalyzerFactory> factories_;
};

}  // namespace llm
}  // namespace analysis
}  // namespace sourcerer

#endif  // SOURCERER_ANALYSIS_LLM_LLM_ANALYZER_REGISTRY_H_
