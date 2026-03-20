// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_ANALYSIS_LLM_DATA_CODE_SCANNER_H_
#define SOURCERER_ANALYSIS_LLM_DATA_CODE_SCANNER_H_

#include <cstdint>
#include <string>
#include <vector>

#include "core/address_map.h"
#include "core/binary.h"
#include "analysis/llm/llm_analyzer.h"

namespace sourcerer {
namespace cpu {
class CpuPlugin;
}  // namespace cpu

namespace analysis {
namespace llm {

// Candidate DATA region that may contain valid CPU instructions.
struct DataCodeCandidate {
  uint32_t start_address;      // First byte of the candidate run
  uint32_t length;             // Number of bytes in the run
  std::string disasm_listing;  // Pre-formatted disassembly for the region
};

// Pass 1 — DATA-as-CODE scanner.
//
// Walks DATA-typed address regions in the AddressMap, disassembles bytes using
// the CpuPlugin, and collects runs of >=3 consecutive non-illegal instructions.
// Returns one DataCodeCandidate per run for later LLM confirmation.
class DataCodeScanner {
 public:
  static constexpr int kMinValidInstructions = 3;

  // Scan DATA regions and return candidates.
  // Returns an empty vector when cpu is null.
  static std::vector<DataCodeCandidate> Scan(
      const core::Binary& binary,
      const core::AddressMap& address_map,
      const cpu::CpuPlugin* cpu);

  // Build LlmAnnotations (POSSIBLE_CODE) for the given candidates without
  // LLM confirmation.  Used when no API key is available.
  static std::vector<LlmAnnotation> BuildAnnotations(
      const std::vector<DataCodeCandidate>& candidates);
};

}  // namespace llm
}  // namespace analysis
}  // namespace sourcerer

#endif  // SOURCERER_ANALYSIS_LLM_DATA_CODE_SCANNER_H_
