// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_ANALYSIS_LLM_LLM_ANALYZER_H_
#define SOURCERER_ANALYSIS_LLM_LLM_ANALYZER_H_

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "core/address_map.h"
#include "core/binary.h"
#include "core/instruction.h"

namespace sourcerer {
namespace cpu {
class CpuPlugin;
}  // namespace cpu

namespace analysis {
namespace llm {

// Annotation type — distinguishes what kind of analysis produced this annotation
enum class AnnotationType {
  INSTRUCTION,    // Standard instruction annotation from code-chunk pass
  STRING_DATA,    // Printable ASCII run found in a DATA region (Pass 2)
  POSSIBLE_CODE,  // DATA region bytes that look like valid instructions (Pass 1)
  CODE_PATTERN,   // Recognised code pattern / idiom in a CODE region (Pass 3)
};

// Result of LLM analysis: improved labels and comments for a chunk of code
struct LlmAnnotation {
  uint32_t address;          // Target address
  std::string label;         // Improved label (empty = no change)
  std::string comment;       // Inline comment (empty = no change)
  AnnotationType type = AnnotationType::INSTRUCTION;
};

// Abstract interface for LLM-based post-disassembly analysis
class LlmAnalyzer {
 public:
  virtual ~LlmAnalyzer() = default;

  // Return the provider name (e.g. "claude", "gpt4")
  virtual std::string Name() const = 0;

  // Configure optional overrides.  Empty strings leave defaults unchanged.
  // model: override the model name (e.g. "claude-opus-4-6")
  // url:   override the API base URL (e.g. "http://localhost:11434/v1/messages")
  virtual void Configure(const std::string& model, const std::string& url) {
    (void)model; (void)url;
  }

  // True if the last Analyze() / AnalyzeExtended() call experienced a
  // connection or authentication failure (distinct from "no annotations found").
  // When true, the caller should treat the run as failed and exit non-zero.
  virtual bool HasFailed() const { return false; }

  // True if the provider has the credentials it needs to make API calls.
  // Checked before the analysis loop; failure exits non-zero immediately.
  virtual bool HasApiKey() const { return true; }

  // Analyze a chunk of disassembled instructions and return annotations.
  // Sets HasFailed() on connection/auth errors; returns empty on any error.
  // chunk_context contains pre-formatted disassembly lines for the LLM.
  virtual std::vector<LlmAnnotation> Analyze(
      const std::string& chunk_context,
      const std::vector<core::Instruction>& instructions) = 0;

  // Extended analysis passes (Passes 1-3): data-as-code, strings, patterns.
  // Called once after all Analyze() chunks complete.
  // Default implementation returns empty (providers may override).
  virtual std::vector<LlmAnnotation> AnalyzeExtended(
      const core::Binary& binary,
      const core::AddressMap& address_map,
      const cpu::CpuPlugin* cpu) {
    (void)binary; (void)address_map; (void)cpu;
    return {};
  }

  // Apply annotations to the address map
  static void ApplyAnnotations(const std::vector<LlmAnnotation>& annotations,
                                core::AddressMap* address_map);
};

// Factory function type for LLM analyzers
using LlmAnalyzerFactory = std::function<std::unique_ptr<LlmAnalyzer>()>;

}  // namespace llm
}  // namespace analysis
}  // namespace sourcerer

#endif  // SOURCERER_ANALYSIS_LLM_LLM_ANALYZER_H_
