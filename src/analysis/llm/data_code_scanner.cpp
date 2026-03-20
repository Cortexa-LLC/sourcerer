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
      if (address_map.GetType(addr) != core::AddressType::DATA) {
        ++addr;
        continue;
      }

      uint32_t run_start = addr;
      std::vector<core::Instruction> run_instructions;
      std::ostringstream listing;

      uint32_t scan_addr = addr;
      while (scan_addr < seg_end) {
        if (address_map.GetType(scan_addr) != core::AddressType::DATA) break;

        size_t offset = scan_addr - seg_start;
        if (offset >= seg_size) break;

        core::Instruction inst =
            cpu->Disassemble(base + offset, seg_size - offset, scan_addr);

        if (inst.bytes.empty() || inst.is_illegal) break;

        run_instructions.push_back(inst);
        listing << "; " << FormatLine(inst) << "\n";
        scan_addr += static_cast<uint32_t>(inst.bytes.size());
      }

      if (static_cast<int>(run_instructions.size()) >= kMinValidInstructions) {
        DataCodeCandidate cand;
        cand.start_address = run_start;
        cand.length = scan_addr - run_start;
        cand.disasm_listing = listing.str();
        candidates.push_back(std::move(cand));
        LOG_DEBUG([&] {
          std::ostringstream dbg;
          dbg << "DataCodeScanner: candidate at $" << std::hex << run_start
              << " len=" << (scan_addr - run_start);
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
