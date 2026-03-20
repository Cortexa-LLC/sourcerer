// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_ANALYSIS_LLM_STRING_SCANNER_H_
#define SOURCERER_ANALYSIS_LLM_STRING_SCANNER_H_

#include <cstdint>
#include <string>
#include <vector>

#include "core/address_map.h"
#include "core/binary.h"
#include "analysis/llm/llm_analyzer.h"

namespace sourcerer {
namespace analysis {
namespace llm {

// Pass 2 — Bytes-as-Strings scanner.
//
// Scans DATA-typed regions in the Binary for runs of >=4 consecutive printable
// ASCII bytes (0x20–0x7E). Runs that are terminated by a zero byte ($00) are
// also recognised (C-style / Pascal strings).
//
// This is a purely heuristic pass — no LLM required.
// Each found run is annotated with a ; "text" comment and, when the region has
// no meaningful label, a suggested label of the form str_XXXX.
class StringScanner {
 public:
  static constexpr int kMinStringLength = 4;
  static constexpr uint8_t kLowPrintable = 0x20;
  static constexpr uint8_t kHighPrintable = 0x7E;

  // Scan DATA regions and return one LlmAnnotation (STRING_DATA) per run.
  // When address_map is null or binary has no segments, returns an empty vector.
  static std::vector<LlmAnnotation> Scan(
      const core::Binary& binary,
      const core::AddressMap& address_map);
};

}  // namespace llm
}  // namespace analysis
}  // namespace sourcerer

#endif  // SOURCERER_ANALYSIS_LLM_STRING_SCANNER_H_
