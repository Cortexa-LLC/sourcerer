// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "analysis/llm/chunk_builder.h"

#include <iomanip>
#include <sstream>

namespace sourcerer {
namespace analysis {
namespace llm {

ChunkBuilder::ChunkBuilder(int instructions_per_chunk)
    : instructions_per_chunk_(instructions_per_chunk) {}

// static
std::string ChunkBuilder::FormatChunk(
    const std::vector<core::Instruction>& instructions,
    const core::AddressMap& address_map) {
  std::ostringstream out;

  for (const auto& inst : instructions) {
    // Address column
    out << "$" << std::hex << std::uppercase << std::setfill('0')
        << std::setw(4) << inst.address << "  ";

    // Bytes column (up to 3 bytes shown, padded)
    int shown = 0;
    for (uint8_t b : inst.bytes) {
      if (shown >= 3) break;
      out << std::setw(2) << static_cast<unsigned>(b) << " ";
      ++shown;
    }
    for (int pad = shown; pad < 3; ++pad) {
      out << "   ";
    }
    out << " ";

    // Existing label (if any)
    auto label = address_map.GetLabel(inst.address);
    if (label) {
      out << std::setfill(' ') << std::left << std::setw(16) << *label
          << std::right << std::setfill('0');
    } else {
      out << std::setfill(' ') << std::setw(16) << "" << std::setfill('0');
    }

    // Mnemonic + operand
    out << std::setfill(' ') << std::left;
    out << std::setw(4) << inst.mnemonic << " " << inst.operand;
    out << std::right << std::setfill('0');

    // Existing comment (if any)
    auto comment = address_map.GetComment(inst.address);
    if (comment) {
      out << "  ; " << *comment;
    }

    out << "\n";
  }

  return out.str();
}

std::vector<std::vector<core::Instruction>> ChunkBuilder::Split(
    const std::vector<core::Instruction>& instructions) const {
  std::vector<std::vector<core::Instruction>> chunks;

  for (size_t i = 0; i < instructions.size(); i += instructions_per_chunk_) {
    size_t end = std::min(i + static_cast<size_t>(instructions_per_chunk_),
                          instructions.size());
    chunks.emplace_back(instructions.begin() + i,
                        instructions.begin() + end);
  }

  return chunks;
}

}  // namespace llm
}  // namespace analysis
}  // namespace sourcerer
