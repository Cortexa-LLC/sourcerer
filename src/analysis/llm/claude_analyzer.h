// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_ANALYSIS_LLM_CLAUDE_ANALYZER_H_
#define SOURCERER_ANALYSIS_LLM_CLAUDE_ANALYZER_H_

#include <string>
#include <vector>

#include "analysis/llm/llm_analyzer.h"

namespace sourcerer {
namespace core {
class Binary;
class AddressMap;
}  // namespace core

namespace cpu {
class CpuPlugin;
}  // namespace cpu

namespace analysis {
namespace llm {

// Concrete LLM analyzer that calls the Anthropic Claude API.
//
// Reads ANTHROPIC_API_KEY from the environment.
// Uses the non-streaming Messages API with tool_use to get structured JSON.
// On connection or auth errors HasFailed() returns true; the caller should
// treat this as a fatal error and exit non-zero.
//
// Tool schema: annotate_code({annotations: [{address, label, comment}]})
class ClaudeAnalyzer : public LlmAnalyzer {
 public:
  ClaudeAnalyzer();
  ~ClaudeAnalyzer() override = default;

  std::string Name() const override { return "claude"; }

  // Override model and/or API URL.  Either may be empty to keep the default.
  // url may be a full endpoint URL (e.g. "http://localhost:11434/v1/messages")
  // or a base URL (e.g. "https://api.anthropic.com"); in the latter case the
  // default path (/v1/messages) is appended.
  void Configure(const std::string& model, const std::string& url) override;

  bool HasFailed() const override { return connection_failed_; }
  bool HasApiKey() const override { return !api_key_.empty(); }

  // Standard instruction-annotation pass (Pass 0).
  std::vector<LlmAnnotation> Analyze(
      const std::string& chunk_context,
      const std::vector<core::Instruction>& instructions) override;

  // Extended analysis: Passes 1-3 (data-as-code, strings, code patterns).
  // Runs after all Analyze() chunks complete.
  std::vector<LlmAnnotation> AnalyzeExtended(
      const core::Binary& binary,
      const core::AddressMap& address_map,
      const cpu::CpuPlugin* cpu) override;

 private:
  static std::string BuildSystemPrompt();
  static std::string BuildUserMessage(const std::string& chunk_context);
  static std::vector<LlmAnnotation> ParseToolResponse(const std::string& json_body);

  // Low-level Claude API call — returns raw JSON body or empty on error.
  // Sets connection_failed_ = true on network or auth failure.
  std::string CallClaude(const std::string& request_json);

  std::string api_key_;
  std::string model_ = "claude-opus-4-5";
  std::string api_base_url_ = "https://api.anthropic.com";
  std::string api_path_ = "/v1/messages";
  bool connection_failed_ = false;

  static constexpr const char* kAnthropicVersion = "2023-06-01";
  static constexpr int kMaxTokens = 4096;
};

}  // namespace llm
}  // namespace analysis
}  // namespace sourcerer

#endif  // SOURCERER_ANALYSIS_LLM_CLAUDE_ANALYZER_H_
