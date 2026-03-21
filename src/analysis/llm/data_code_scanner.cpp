// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "analysis/llm/data_code_scanner.h"

#include <iomanip>
#include <sstream>

#include "cpu/cpu_plugin.h"
#include "utils/logger.h"

namespace sourcerer {
namespace analysis {
namespace llm {

namespace {

// Returns true for address types that may contain hidden code.
bool IsScannable(core::AddressType t) {
  return t == core::AddressType::DATA || t == core::AddressType::UNKNOWN;
}

// Returns a vector of BinarySegment views covering all binary data,
// handling both flat (data_) and multi-segment (segments_) binaries.
std::vector<core::BinarySegment> AllSegments(const core::Binary& binary) {
  if (!binary.segments().empty()) {
    return binary.segments();
  }
  if (!binary.data().empty()) {
    core::BinarySegment seg;
    seg.data = binary.data();
    seg.load_address = binary.load_address();
    return {std::move(seg)};
  }
  return {};
}

// Format a single instruction as a disassembly comment line.
std::string FormatLine(const core::Instruction& inst) {
  std::ostringstream oss;
  oss << "$" << std::hex << std::setw(4) << std::setfill('0')
      << std::uppercase << inst.address << "  ";
  for (size_t i = 0; i < inst.bytes.size() && i < 3; ++i) {
    oss << std::hex << std::setw(2) << std::setfill('0')
        << std::uppercase << static_cast<int>(inst.bytes[i]) << " ";
  }
  for (size_t i = inst.bytes.size(); i < 3; ++i) oss << "   ";
  oss << "  " << inst.mnemonic;
  if (!inst.operand.empty()) oss << " " << inst.operand;
  return oss.str();
}

}  // namespace

// static
std::vector<DataCodeCandidate> DataCodeScanner::Scan(
    const core::Binary& binary,
    const core::AddressMap& address_map,
    const cpu::CpuPlugin* cpu) {
  std::vector<DataCodeCandidate> candidates;
  if (!cpu) return candidates;

  auto segs = AllSegments(binary);
  if (segs.empty()) return candidates;

  for (const auto& seg : segs) {
    const uint8_t* base = seg.data.data();
    const size_t seg_size = seg.data.size();
    const uint32_t seg_start = seg.load_address;
    const uint32_t seg_end = seg_start + static_cast<uint32_t>(seg_size);

    uint32_t addr = seg_start;
    while (addr < seg_end) {
      if (!IsScannable(address_map.GetType(addr))) {
        ++addr;
        continue;
      }

      uint32_t run_start = addr;
      std::vector<core::Instruction> run_instructions;
      std::ostringstream listing;

      uint32_t scan_addr = addr;
      int illegal_count = 0;
      while (scan_addr < seg_end) {
        if (!IsScannable(address_map.GetType(scan_addr))) break;

        size_t offset = scan_addr - seg_start;
        if (offset >= seg_size) break;

        core::Instruction inst =
            cpu->Disassemble(base + offset, seg_size - offset, scan_addr);

        if (inst.bytes.empty()) break;

        if (inst.is_illegal) {
          // Skip illegal bytes rather than aborting the run.  NMOS 6502 code
          // can contain undocumented opcodes; a single illegal byte should not
          // prevent detection of an RTS or JMP that follows.
          ++illegal_count;
          ++scan_addr;
          continue;
        }

        run_instructions.push_back(inst);
        listing << "; " << FormatLine(inst) << "\n";
        scan_addr += static_cast<uint32_t>(inst.bytes.size());

        // Stop at flow-control terminators (RTS/RTI/JMP abs/JMP ind) so we
        // don't over-extend into unrelated data after the subroutine.
        const uint8_t op = inst.bytes[0];
        if (op == 0x60 || op == 0x40 || op == 0x4C || op == 0x6C) break;
      }

      // Require enough valid instructions AND that illegal bytes don't
      // dominate (≤ 50% of total bytes scanned).
      const int total_insts =
          static_cast<int>(run_instructions.size()) + illegal_count;
      const bool density_ok =
          (total_insts == 0) || (illegal_count * 2 <= total_insts);

      if (static_cast<int>(run_instructions.size()) >= kMinValidInstructions &&
          density_ok) {
        DataCodeCandidate cand;
        cand.start_address = run_start;
        cand.length = scan_addr - run_start;
        cand.disasm_listing = listing.str();
        candidates.push_back(std::move(cand));
        LOG_DEBUG([&] {
          std::ostringstream dbg;
          dbg << "DataCodeScanner: candidate at $" << std::hex << run_start
              << " len=" << (scan_addr - run_start)
              << " illegal=" << illegal_count;
          return dbg.str();
        }());
        addr = scan_addr;
      } else {
        ++addr;
      }
    }
  }

  return candidates;
}

// static
std::vector<LlmAnnotation> DataCodeScanner::BuildAnnotations(
    const std::vector<DataCodeCandidate>& candidates) {
  std::vector<LlmAnnotation> annotations;
  annotations.reserve(candidates.size());
  for (const auto& cand : candidates) {
    LlmAnnotation ann;
    ann.address = cand.start_address;
    ann.label = "";
    ann.comment = "; *** POSSIBLE CODE — review and add to hints file ***\n"
                  + cand.disasm_listing;
    ann.type = AnnotationType::POSSIBLE_CODE;
    annotations.push_back(std::move(ann));
  }
  return annotations;
}

}  // namespace llm
}  // namespace analysis
}  // namespace sourcerer
