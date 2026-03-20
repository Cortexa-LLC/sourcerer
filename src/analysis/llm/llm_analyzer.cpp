// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "analysis/llm/llm_analyzer.h"

namespace sourcerer {
namespace analysis {
namespace llm {

// static
void LlmAnalyzer::ApplyAnnotations(const std::vector<LlmAnnotation>& annotations,
                                    core::AddressMap* address_map) {
  if (!address_map) return;

  for (const auto& ann : annotations) {
    if (!ann.label.empty()) {
      address_map->SetLabel(ann.address, ann.label);
    }
    if (!ann.comment.empty()) {
      address_map->SetComment(ann.address, ann.comment);
    }
  }
}

}  // namespace llm
}  // namespace analysis
}  // namespace sourcerer
