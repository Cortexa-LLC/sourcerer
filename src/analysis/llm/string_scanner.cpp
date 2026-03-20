// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "analysis/llm/string_scanner.h"

#include <iomanip>
#include <sstream>

#include "utils/logger.h"

namespace sourcerer {
namespace analysis {
namespace llm {

namespace {

// Returns all segments of the binary (flat or multi-segment).
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

inline bool IsPrintable(uint8_t b) {
  return b >= StringScanner::kLowPrintable && b <= StringScanner::kHighPrintable;
}

}  // namespace

// static
std::vector<LlmAnnotation> StringScanner::Scan(
    const core::Binary& binary,
    const core::AddressMap& address_map) {
  std::vector<LlmAnnotation> annotations;

  auto segs = AllSegments(binary);
  if (segs.empty()) return annotations;

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
      std::string text;
      uint32_t scan_addr = addr;
      while (scan_addr < seg_end) {
        if (address_map.GetType(scan_addr) != core::AddressType::DATA) break;
        size_t offset = scan_addr - seg_start;
        if (offset >= seg_size) break;
        uint8_t b = base[offset];
        if (!IsPrintable(b)) {
          // Allow a single null terminator to close the run.
          if (b == 0x00 && !text.empty()) ++scan_addr;
          break;
        }
        text += static_cast<char>(b);
        ++scan_addr;
      }

      if (static_cast<int>(text.size()) >= kMinStringLength) {
        LlmAnnotation ann;
        ann.address = run_start;
        ann.type = AnnotationType::STRING_DATA;
        ann.comment = "; \"" + text + "\"";

        // Suggest a label if none already exists.
        auto existing_label = address_map.GetLabel(run_start);
        if (!existing_label || existing_label->empty()) {
          std::ostringstream oss;
          oss << "str_" << std::hex << std::uppercase
              << std::setw(4) << std::setfill('0') << run_start;
          ann.label = oss.str();
        }

        LOG_DEBUG([&] {
          std::ostringstream dbg;
          dbg << "StringScanner: found string at $" << std::hex << run_start
              << " = \"" << text << "\"";
          return dbg.str();
        }());
        annotations.push_back(std::move(ann));
        addr = scan_addr;
      } else {
        ++addr;
      }
    }
  }

  return annotations;
}

}  // namespace llm
}  // namespace analysis
}  // namespace sourcerer
