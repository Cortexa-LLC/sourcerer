// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "output/scmasm_formatter.h"

#include <iomanip>
#include <sstream>
#include <regex>

#include "analysis/equate_generator.h"

namespace sourcerer {
namespace output {

// Helper: Extract address from operand string
static uint32_t ExtractAddressFromOperand(const std::string& operand) {
  std::regex hex_regex(R"(\$([0-9A-Fa-f]+))");
  std::smatch match;
  
  if (std::regex_search(operand, match, hex_regex)) {
    return std::stoul(match[1].str(), nullptr, 16);
  }
  
  return 0xFFFFFFFF;  // Invalid address
}

// Helper: Replace address in operand with symbol name
static std::string SubstituteSymbol(const std::string& operand, 
                                    uint32_t address,
                                    const std::string& symbol_name) {
  std::ostringstream addr_str;
  addr_str << "$" << std::hex << std::uppercase << std::setw(4) 
           << std::setfill('0') << address;
  
  std::string result = operand;
  size_t pos = result.find(addr_str.str());
  if (pos != std::string::npos) {
    result.replace(pos, addr_str.str().length(), symbol_name);
  }
  
  return result;
}

std::string ScmasmFormatter::Format(
    const core::Binary& binary,
    const std::vector<core::Instruction>& instructions,
    const core::AddressMap* address_map,
    const core::SymbolTable* symbol_table,
    const analysis::EquateGenerator* equate_gen) {
  
  std::ostringstream out;

  // Header
  out << FormatHeader(binary);

  // Output .EQ statements for generated equates
  if (equate_gen) {
    const auto& equates = equate_gen->GetEquates();
    if (!equates.empty()) {
      for (const auto& pair : equates) {
        uint8_t value = pair.first;
        const std::string& name = pair.second;
        out << name;
        out << std::string(std::max(1, OPCODE_COL - static_cast<int>(name.length())), ' ');
        out << ".EQ   $" << std::hex << std::uppercase << std::setw(2)
            << std::setfill('0') << static_cast<int>(value);

        // Add comment if available
        std::string comment = equate_gen->GetEquateComment(value);
        if (!comment.empty()) {
          int line_length = name.length() + (OPCODE_COL - name.length()) + 10;  // ".EQ   $XX"
          if (line_length < COMMENT_COL) {
            out << std::string(COMMENT_COL - line_length, ' ');
            out << comment;  // SCMASM doesn't use ; for comments
          }
        }
        out << std::endl;
      }
      out << std::endl;  // Blank line after generated equates
    }
  }

  // .OR directive (SCMASM uses dot prefix)
  out << std::string(OPCODE_COL, ' ') << ".OR   ";
  out << "$" << FormatAddress(binary.load_address(), 4);
  out << std::endl << std::endl;

  // Instructions
  for (const auto& inst : instructions) {
    // Check if this instruction has a subroutine label - add separator if so
    if (address_map && address_map->HasLabel(inst.address)) {
      std::string label = address_map->GetLabel(inst.address);
      if (IsSubroutineLabel(label)) {
        out << "*--------------------------------" << std::endl;
      }
    }

    out << FormatInstruction(inst, address_map, symbol_table, equate_gen) << std::endl;
  }

  // Footer
  out << std::endl << FormatFooter();

  // Add line numbers to all lines (SCMASM format)
  return AddLineNumbers(out.str());
}

std::string ScmasmFormatter::FormatInstruction(
    const core::Instruction& inst,
    const core::AddressMap* address_map,
    const core::SymbolTable* symbol_table,
    const analysis::EquateGenerator* equate_gen) {
  
  std::ostringstream out;

  // Label column (if applicable)
  std::string label = GetLabel(inst.address, address_map);
  if (!label.empty()) {
    out << label;
  }

  // Pad to opcode column
  int current_col = label.length();
  if (current_col < OPCODE_COL) {
    out << std::string(OPCODE_COL - current_col, ' ');
  } else if (current_col > 0) {
    // Label is too long, put opcode on next line
    out << std::endl << std::string(OPCODE_COL, ' ');
  }

  // Opcode (mnemonic)
  out << std::left << std::setw(5) << inst.mnemonic;

  // Operand with equate and symbol substitution
  if (!inst.operand.empty()) {
    std::string operand = inst.operand;
    bool substituted = false;

    // Priority 0: Try equate substitution for immediate values (#$XX)
    if (equate_gen && operand.find("#$") != std::string::npos) {
      size_t pos = operand.find("#$");
      std::string hex_str = operand.substr(pos + 2);
      try {
        uint32_t value = std::stoul(hex_str, nullptr, 16);
        if (value <= 0xFF && equate_gen->HasEquate(static_cast<uint8_t>(value))) {
          std::string equate_name = equate_gen->GetEquateName(static_cast<uint8_t>(value));
          operand = operand.substr(0, pos + 1) + equate_name;  // Keep the '#' prefix
          substituted = true;
        }
      } catch (...) {
        // Skip malformed values
      }
    }

    // Priority 1: Try to substitute symbols if symbol table is available
    if (!substituted && symbol_table) {
      uint32_t addr = ExtractAddressFromOperand(operand);
      if (addr != 0xFFFFFFFF && symbol_table->HasSymbol(addr)) {
        operand = SubstituteSymbol(operand, addr,
                                    symbol_table->GetSymbolName(addr));
        substituted = true;
      }
    }
    
    // Check address map for labels on target addresses
    if (address_map && inst.target_address != 0) {
      if (address_map->HasLabel(inst.target_address)) {
        operand = address_map->GetLabel(inst.target_address);
      }
    }
    
    out << " " << operand;
  }

  // Comment column
  int line_length = OPCODE_COL + 5;
  if (!inst.operand.empty()) {
    line_length += 1 + inst.operand.length();
  }

  if (line_length < COMMENT_COL) {
    out << std::string(COMMENT_COL - line_length, ' ');

    // Check for user comment from AddressMap
    if (address_map && address_map->HasComment(inst.address)) {
      out << address_map->GetComment(inst.address);
    } else if (inst.is_branch) {
      // Add contextual branch comment
      std::string branch_comment = GenerateBranchComment(inst.mnemonic);
      if (!branch_comment.empty()) {
        out << branch_comment;
      } else {
        out << "$" << FormatAddress(inst.address, 4);
      }
    } else {
      // Default comment shows address (SCMASM format doesn't use ; prefix)
      out << "$" << FormatAddress(inst.address, 4);
    }
  }

  return out.str();
}

std::string ScmasmFormatter::FormatData(uint32_t address,
                                       const std::vector<uint8_t>& bytes) {
  (void)address;  // Unused parameter - may be used for labels in future
  std::ostringstream out;

  // Use .DA (Define ASCII) directive for data in SCMASM
  out << std::string(OPCODE_COL, ' ') << ".DA   ";

  for (size_t i = 0; i < bytes.size(); ++i) {
    if (i > 0) out << ",";
    out << "$" << std::hex << std::uppercase 
        << std::setw(2) << std::setfill('0') 
        << static_cast<int>(bytes[i]);
  }

  return out.str();
}

std::string ScmasmFormatter::FormatHeader(const core::Binary& binary) {
  std::ostringstream out;

  out << "*---------------------------------------" << std::endl;
  out << "* Sourcerer - Modern Multi-CPU Disassembler" << std::endl;
  out << "* Source: " << binary.source_file() << std::endl;
  out << "* Load Address: $" << FormatAddress(binary.load_address(), 4) << std::endl;
  out << "* Size: " << binary.size() << " bytes" << std::endl;
  out << "*---------------------------------------" << std::endl;
  out << std::endl;

  return out.str();
}

std::string ScmasmFormatter::FormatFooter() {
  std::ostringstream out;
  // SCMASM uses .TF instead of CHK
  out << std::string(OPCODE_COL, ' ') << ".TF" << std::endl;
  return out.str();
}

std::string ScmasmFormatter::FormatAddress(uint32_t address, int width) const {
  std::ostringstream out;
  out << std::hex << std::uppercase 
      << std::setw(width) << std::setfill('0') 
      << address;
  return out.str();
}

std::string ScmasmFormatter::GetLabel(uint32_t address,
                                     const core::AddressMap* address_map) const {
  if (!address_map) {
    return "";
  }

  // Check if there's a label for this address
  if (address_map->HasLabel(address)) {
    return address_map->GetLabel(address);
  }

  return "";
}

bool ScmasmFormatter::IsSubroutineLabel(const std::string& label) const {
  if (label.empty()) {
    return false;
  }

  // Local labels (starting with . or :) are not subroutines
  if (label[0] == '.' || label[0] == ':') {
    return false;
  }

  // Branch labels (L_xxxx) are not subroutines
  if (label.find("L_") == 0) {
    return false;
  }

  // Data labels are not subroutines
  if (label.find("DATA_") == 0) {
    return false;
  }

  // Zero page labels are not subroutines
  if (label.find("ZP_") == 0) {
    return false;
  }

  // Everything else is considered a subroutine
  // This includes: SUB_xxxx, MAIN, START_xxxx, IO_xxxx, ROM_xxxx, and user labels
  return true;
}

std::string ScmasmFormatter::FormatLineNumber(int line_num) const {
  std::ostringstream out;
  out << std::setw(4) << std::setfill('0') << line_num << " ";
  return out.str();
}

std::string ScmasmFormatter::AddLineNumbers(const std::string& text) const {
  std::istringstream input(text);
  std::ostringstream output;
  std::string line;
  int line_num = LINE_NUMBER_START;

  while (std::getline(input, line)) {
    // Add line number to non-empty lines
    // Empty lines also get line numbers in SCMASM format
    output << FormatLineNumber(line_num) << line << std::endl;
    line_num += LINE_NUMBER_INCREMENT;
  }

  return output.str();
}

std::string ScmasmFormatter::GenerateBranchComment(const std::string& mnemonic) const {
  // Generate contextual comments for branch instructions
  // Using SCMASM convention with "..." prefix

  if (mnemonic == "BCS") return "...CARRY SET";
  if (mnemonic == "BCC") return "...CARRY CLEAR";
  if (mnemonic == "BEQ") return "...EQUAL / ZERO";
  if (mnemonic == "BNE") return "...NOT EQUAL / NOT ZERO";
  if (mnemonic == "BMI") return "...MINUS / NEGATIVE";
  if (mnemonic == "BPL") return "...PLUS / POSITIVE";
  if (mnemonic == "BVS") return "...OVERFLOW SET";
  if (mnemonic == "BVC") return "...OVERFLOW CLEAR";
  if (mnemonic == "BRA") return "...ALWAYS";  // 65C02

  return "";  // No comment for non-branch instructions
}

std::unique_ptr<Formatter> CreateScmasmFormatter() {
  return std::make_unique<ScmasmFormatter>();
}

}  // namespace output
}  // namespace sourcerer
