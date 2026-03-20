// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_ANALYSIS_LLM_CHUNK_BUILDER_H_
#define SOURCERER_ANALYSIS_LLM_CHUNK_BUILDER_H_

#include <string>
#include <vector>

#include "core/address_map.h"
#include "core/instruction.h"

namespace sourcerer {
namespace analysis {
namespace llm {

// Splits a disassembly instruction list into text chunks suitable for LLM
// context windows, and formats each chunk as a human-readable listing.
class ChunkBuilder {
 public:
  // instructions_per_chunk: max instructions per chunk sent to the LLM.
  explicit ChunkBuilder(int instructions_per_chunk = 200);

  // Format a single chunk of instructions as a text listing.
  // Each line: "$ADDR  HH HH HH  MNEMONIC OPERAND  ; existing_comment"
  static std::string FormatChunk(
      const std::vector<core::Instruction>& instructions,
      const core::AddressMap& address_map);

  // Split instructions into chunks of at most max_per_chunk each.
  std::vector<std::vector<core::Instruction>> Split(
      const std::vector<core::Instruction>& instructions) const;

 private:
  int instructions_per_chunk_;
};

}  // namespace llm
}  // namespace analysis
}  // namespace sourcerer

#endif  // SOURCERER_ANALYSIS_LLM_CHUNK_BUILDER_H_
