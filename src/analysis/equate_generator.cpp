// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "analysis/equate_generator.h"

#include <iomanip>
#include <sstream>

namespace sourcerer {
namespace analysis {

void EquateGenerator::AnalyzeInstructions(
    const std::vector<core::Instruction>& instructions) {
  value_counts_.clear();
  equates_.clear();
  equate_comments_.clear();

  // Count immediate value usage
  for (const auto& inst : instructions) {
    // Check if this is an immediate mode instruction (e.g., "LDA #$FF")
    if (inst.operand.find("#$") != std::string::npos) {
      // Extract the immediate value
      size_t pos = inst.operand.find("#$");
      std::string hex_str = inst.operand.substr(pos + 2);

      // Parse hex value (could be 1 or 2 digits)
      try {
        uint32_t value = std::stoul(hex_str, nullptr, 16);
        if (value <= 0xFF) {
          value_counts_[static_cast<uint8_t>(value)]++;
        }
      } catch (...) {
        // Skip malformed values
      }
    }
  }

  // Generate equates for frequently used values
  for (const auto& pair : value_counts_) {
    uint8_t value = pair.first;
    int count = pair.second;

    if (count >= min_usage_count_) {
      equates_[value] = GenerateEquateName(value, count);
      // Generate comment for this equate
      std::ostringstream comment;
      if (value >= 0xC0 && value <= 0xD1) {
        comment << "ProDOS MLI call code";
      } else {
        switch (value) {
          case 0x00: comment << "Zero value"; break;
          case 0x01: comment << "One value"; break;
          case 0x08: comment << "Backspace character"; break;
          case 0x0D: comment << "Carriage return"; break;
          case 0x20: comment << "Space character"; break;
          case 0x80: comment << "High bit mask"; break;
          case 0xFF: comment << "Maximum byte value"; break;
          default:
            comment << "Used " << count << " time" << (count > 1 ? "s" : "");
            break;
        }
      }
      equate_comments_[value] = comment.str();
    }
  }
}

bool EquateGenerator::HasEquate(uint8_t value) const {
  return equates_.find(value) != equates_.end();
}

std::string EquateGenerator::GetEquateName(uint8_t value) const {
  auto it = equates_.find(value);
  if (it != equates_.end()) {
    return it->second;
  }
  return "";
}

std::string EquateGenerator::GetEquateComment(uint8_t value) const {
  auto it = equate_comments_.find(value);
  if (it != equate_comments_.end()) {
    return it->second;
  }
  return "";
}

int EquateGenerator::GetUsageCount(uint8_t value) const {
  auto it = value_counts_.find(value);
  if (it != value_counts_.end()) {
    return it->second;
  }
  return 0;
}

std::string EquateGenerator::GenerateEquateName(uint8_t value,
                                                 int usage_count) const {
  (void)usage_count;  // Unused - kept for consistency
  std::ostringstream oss;

  // Special cases for common values
  switch (value) {
    case 0x00:
      return "ZERO";
    case 0x01:
      return "ONE";
    case 0x08:
      return "BACKSPACE";
    case 0x0D:
      return "CR";
    case 0x20:
      return "SPACE";
    case 0x80:
      return "HIGHBIT";
    case 0xFF:
      return "MAX_BYTE";
    default:
      break;
  }

  // ProDOS MLI call codes ($C0-$D1)
  if (value >= 0xC0 && value <= 0xD1) {
    switch (value) {
      case 0xC0: return "MLI_CREATE";
      case 0xC1: return "MLI_DESTROY";
      case 0xC2: return "MLI_RENAME";
      case 0xC3: return "MLI_SETINFO";
      case 0xC4: return "MLI_GETINFO";
      case 0xC5: return "MLI_ONLINE";
      case 0xC6: return "MLI_SETPREFIX";
      case 0xC7: return "MLI_GETPREFIX";
      case 0xC8: return "MLI_OPEN";
      case 0xC9: return "MLI_NEWLINE";
      case 0xCA: return "MLI_READ";
      case 0xCB: return "MLI_WRITE";
      case 0xCC: return "MLI_CLOSE";
      case 0xCD: return "MLI_FLUSH";
      case 0xCE: return "MLI_SETMARK";
      case 0xCF: return "MLI_GETMARK";
      case 0xD0: return "MLI_SETEOF";
      case 0xD1: return "MLI_GETEOF";
      default:
        oss << "MLI_" << std::hex << std::uppercase << std::setw(2)
            << std::setfill('0') << static_cast<int>(value);
        return oss.str();
    }
  }

  // Generic name based on value
  oss << "CONST_" << std::hex << std::uppercase << std::setw(2)
      << std::setfill('0') << static_cast<int>(value);
  return oss.str();
}

}  // namespace analysis
}  // namespace sourcerer
