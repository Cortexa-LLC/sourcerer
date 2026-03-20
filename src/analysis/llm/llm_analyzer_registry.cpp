// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "analysis/llm/llm_analyzer_registry.h"

#include "analysis/llm/claude_analyzer.h"
#include "utils/logger.h"

namespace sourcerer {
namespace analysis {
namespace llm {

LlmAnalyzerRegistry& LlmAnalyzerRegistry::Instance() {
  static LlmAnalyzerRegistry instance;
  return instance;
}

LlmAnalyzerRegistry::LlmAnalyzerRegistry() {
  RegisterBuiltinProviders();
}

void LlmAnalyzerRegistry::RegisterBuiltinProviders() {
  Register("claude", []() -> std::unique_ptr<LlmAnalyzer> {
    return std::make_unique<ClaudeAnalyzer>();
  });
  LOG_DEBUG("Registered built-in LLM analyzer: claude");
}

void LlmAnalyzerRegistry::Register(const std::string& name,
                                    LlmAnalyzerFactory factory) {
  factories_[name] = std::move(factory);
}

std::unique_ptr<LlmAnalyzer> LlmAnalyzerRegistry::Create(
    const std::string& name) const {
  auto it = factories_.find(name);
  if (it == factories_.end()) {
    return nullptr;
  }
  return it->second();
}

std::vector<std::string> LlmAnalyzerRegistry::ListProviders() const {
  std::vector<std::string> names;
  names.reserve(factories_.size());
  for (const auto& kv : factories_) {
    names.push_back(kv.first);
  }
  return names;
}

bool LlmAnalyzerRegistry::Has(const std::string& name) const {
  return factories_.find(name) != factories_.end();
}

}  // namespace llm
}  // namespace analysis
}  // namespace sourcerer
