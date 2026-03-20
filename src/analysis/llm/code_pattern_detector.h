// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_ANALYSIS_LLM_CODE_PATTERN_DETECTOR_H_
#define SOURCERER_ANALYSIS_LLM_CODE_PATTERN_DETECTOR_H_

#include <cstdint>
#include <string>
#include <vector>

#include "core/address_map.h"
#include "core/binary.h"
#include "core/instruction.h"
#include "analysis/llm/llm_analyzer.h"

namespace sourcerer {
namespace analysis {
namespace llm {

// Categories of recognised vintage assembly idioms.
enum class CodePattern {
  UNKNOWN = 0,
  STRING_OP,      // String copy/compare/search/length
  GRAPHICS,       // Pixel, line, fill, sprite, HIRES/LORES setup
  MATH,           // Multiply/divide, BCD arithmetic, 16-bit add/subtract
  MEMORY_OP,      // Block move/clear/fill
  IO_POLLING,     // Keyboard poll, printer output, wait-for-keypress
  DISPATCH_TABLE, // Jump table / state machine
  ISR_HANDLER,    // Interrupt service routine (PHP/PHA prologue + RTI epilogue)
};

// A subroutine (or basic block) that matched one of the pattern heuristics.
struct PatternCandidate {
  uint32_t start_address;  // Entry address of the subroutine / block
  uint32_t end_address;    // Inclusive last byte
  CodePattern pattern;     // Best matching pattern category
  std::vector<core::Instruction> instructions;  // All instructions in the block
  std::string disasm_listing;  // Pre-formatted listing for LLM
};

// Pass 3 — Code Pattern Recognition.
//
// Two-layer approach:
//   1. Heuristic pre-filter: fast scan to find subroutines matching known
//      vintage assembly idioms — avoids sending every subroutine to the LLM.
//   2. LLM confirmation + documentation: ClaudeAnalyzer passes candidates
//      to Claude for a function name, description, and key comments.
class CodePatternDetector {
 public:
  // Minimum number of instructions in a block to be considered.
  static constexpr int kMinInstructions = 3;

  // Identify subroutines / blocks matching heuristic patterns.
  // Returns candidates sorted by start_address.
  static std::vector<PatternCandidate> Detect(
      const core::Binary& binary,
      const core::AddressMap& address_map,
      const std::vector<core::Instruction>& all_instructions);

  // Return a human-readable name for a CodePattern value.
  static std::string PatternName(CodePattern p);
};

}  // namespace llm
}  // namespace analysis
}  // namespace sourcerer

#endif  // SOURCERER_ANALYSIS_LLM_CODE_PATTERN_DETECTOR_H_
