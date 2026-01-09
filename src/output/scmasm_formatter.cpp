// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "output/scmasm_formatter.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <regex>

#include "output/data_collector.h"
#include "output/address_analyzer.h"
#include "output/label_resolver.h"

namespace sourcerer {
namespace output {

std::string ScmasmFormatter::Format(
    const core::Binary& binary,
    const std::vector<core::Instruction>& instructions,
    const core::AddressMap* address_map,
    const core::SymbolTable* symbol_table,
    const core::IEquateProvider* equate_gen) {

  std::ostringstream out;

  // Create components for this formatting session
  DataCollector data_collector(&binary);
  AddressAnalyzer address_analyzer(&binary, address_map);
  LabelResolver label_resolver(address_map, symbol_table);

  // Header
  out << FormatHeader(binary);

  // Collect all referenced addresses from instructions and data
  auto referenced_addresses = address_analyzer.CollectReferencedAddresses(instructions);

  // Output .EQ statements for platform symbols that are referenced
  if (symbol_table) {
    std::set<std::string> output_symbols;  // Track to avoid duplicates
    for (uint32_t ref_addr : referenced_addresses) {
      if (auto symbol_name = symbol_table->GetSymbolName(ref_addr)) {
        if (output_symbols.find(*symbol_name) == output_symbols.end()) {
          out << *symbol_name;
          out << std::string(std::max(1, OPCODE_COL - static_cast<int>(symbol_name->length())), ' ');
          out << ".EQ   $" << FormatAddress(ref_addr, 4) << std::endl;
          output_symbols.insert(*symbol_name);
        }
      }
    }
    if (!output_symbols.empty()) {
      out << std::endl;  // Blank line after platform symbols
    }
  }

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

  // Build instruction map for quick lookup
  std::map<uint32_t, core::Instruction> inst_map;
  for (const auto& inst : instructions) {
    inst_map[inst.address] = inst;
  }

  // Walk through binary in address order
  uint32_t addr = binary.load_address();
  uint32_t end_addr = addr + binary.size();

  while (addr < end_addr) {
    // Check if we have an instruction at this address
    if (inst_map.count(addr) > 0) {
      // Check if this instruction has a subroutine label - add separator if so
      if (address_map) {
        if (auto label = address_map->GetLabel(addr)) {
          if (IsSubroutineLabel(*label)) {
            out << "*--------------------------------" << std::endl;
          }
        }
      }

      // Output the instruction
      out << FormatInstruction(inst_map[addr], address_map, symbol_table, equate_gen)
          << std::endl;
      addr += inst_map[addr].bytes.size();
    } else if (address_map && address_map->GetType(addr) != core::AddressType::CODE) {
      // Data region - collect intelligently
      std::vector<uint8_t> data_bytes;
      uint32_t data_start = addr;

      // Check if next few bytes look like a string
      auto string_detection = data_collector.DetectString(addr, end_addr, 4);
      bool looks_like_string = string_detection.looks_like_string;

      if (looks_like_string && address_map) {
        // Collect string data
        auto string_result = data_collector.CollectStringData(
            addr, end_addr, address_map, 128);
        data_bytes = string_result.bytes;
        addr = string_result.next_address;
      }

      // Fall back to binary data collection if string collection failed
      if (data_bytes.empty()) {
        auto binary_result = data_collector.CollectBinaryData(
            data_start, end_addr, address_map, 8);
        data_bytes = binary_result.bytes;
        addr = binary_result.next_address;
      }

      // Format data region (includes UNKNOWN as .DA)
      if (!data_bytes.empty()) {
        out << FormatDataRegion(data_start, data_bytes, address_map, symbol_table, &binary)
            << std::endl;
      } else {
        // Should not happen anymore since we collect UNKNOWN too
        addr++;
      }
    } else {
      // address_map says CODE but no instruction at this address
      // This can happen for orphaned CODE bytes or mid-instruction bytes
      // Output as .DA data to ensure complete coverage
      std::vector<uint8_t> orphan_bytes;
      uint32_t orphan_start = addr;

      while (addr < end_addr && inst_map.count(addr) == 0 &&
             orphan_bytes.size() < 8) {
        // Only collect if it's actually CODE (or no address_map)
        if (address_map && address_map->GetType(addr) != core::AddressType::CODE) {
          break;  // Hit a DATA/UNKNOWN byte, stop collecting
        }
        // Stop if this address has a label (it needs its own output line)
        if (addr != orphan_start && address_map && address_map->HasLabel(addr)) {
          break;
        }
        const uint8_t* byte = binary.GetPointer(addr);
        if (byte) {
          orphan_bytes.push_back(*byte);
        }
        addr++;
      }

      if (!orphan_bytes.empty()) {
        // Output label if present (on its own line)
        if (address_map) {
          if (auto label = address_map->GetLabel(orphan_start)) {
            out << *label << std::endl;
          }
        }
        // Don't pass address_map to FormatDataRegion to avoid duplicate label output
        out << FormatDataRegion(orphan_start, orphan_bytes, nullptr, symbol_table, &binary)
            << std::endl;
      }
    }
  }

  // Footer (empty to avoid adding extra bytes)
  out << std::endl;

  // Add line numbers to all lines (SCMASM format)
  return AddLineNumbers(out.str());
}

std::string ScmasmFormatter::FormatInstruction(
    const core::Instruction& inst,
    const core::AddressMap* address_map,
    const core::SymbolTable* symbol_table,
    const core::IEquateProvider* equate_gen) {

  std::ostringstream out;

  // Create label resolver for this instruction
  LabelResolver label_resolver(address_map, symbol_table);

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

  // Operand with symbol and equate substitution
  std::string final_operand;
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

    // Priority 1 & 2: Try symbol table and address map (handled by SubstituteLabel)
    if (!substituted) {
      auto label_result = label_resolver.SubstituteLabel(operand);
      if (label_result.substituted) {
        operand = label_result.operand;
        substituted = true;
      }
    }

    // Priority 3: For branch/jump instructions, use target_address from address_map
    // Only substitute if the target address has an instruction or is at a valid boundary
    if (!substituted && address_map && inst.target_address != 0) {
      if (auto label = address_map->GetLabel(inst.target_address)) {
        if (address_map->IsCode(inst.target_address) || address_map->IsData(inst.target_address)) {
          operand = *label;
        }
      }
    }

    final_operand = operand;
    out << " " << operand;
  }

  // Comment column - calculate based on actual output length
  int line_length = OPCODE_COL + 5;
  if (!final_operand.empty()) {
    line_length += 1 + final_operand.length();
  }

  if (line_length < COMMENT_COL) {
    out << std::string(COMMENT_COL - line_length, ' ');

    // Check for user comment from AddressMap
    bool has_comment = false;
    if (address_map) {
      if (auto comment = address_map->GetComment(inst.address)) {
        out << *comment;
        has_comment = true;
      }
    }

    // Check for ROM routine description for JSR/LBSR/BSR
    if (!has_comment && inst.is_call && inst.target_address != 0 && symbol_table) {
      if (auto symbol = symbol_table->GetSymbol(inst.target_address)) {
        if (!symbol->description.empty() && symbol->type == core::SymbolType::ROM_ROUTINE) {
          out << symbol->description;  // SCMASM doesn't use ; prefix
          has_comment = true;
        }
      }
    }

    if (!has_comment) {
      if (inst.is_branch) {
        // Add contextual branch comment
        std::string branch_comment = GenerateBranchComment(inst.mnemonic);
        if (!branch_comment.empty()) {
          out << branch_comment;
        }
        // No else - don't add useless address comments
      }
      // No default address comment - only meaningful comments
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

std::string ScmasmFormatter::FormatDataRegion(uint32_t address,
                                             const std::vector<uint8_t>& bytes,
                                             const core::AddressMap* address_map,
                                             const core::SymbolTable* symbol_table,
                                             const core::Binary* binary) {
  (void)symbol_table;  // Unused for now
  (void)binary;        // Unused for now
  std::ostringstream out;

  // Output label if present
  if (address_map) {
    if (auto label = address_map->GetLabel(address)) {
      out << *label << std::endl;
    }
  }

  // Check for string: either all bytes are printable, OR there's an embedded string
  bool is_pure_string = bytes.size() >= 3;
  for (size_t i = 0; i < bytes.size() && is_pure_string; ++i) {
    // CRITICAL: Reject high-bit bytes (graphics data, not ASCII)
    if (bytes[i] >= 0x80) {
      is_pure_string = false;
      break;
    }
    // CRITICAL: Reject control characters (except CR/LF)
    if (bytes[i] < 0x20 && bytes[i] != 0x0D && bytes[i] != 0x0A) {
      is_pure_string = false;
      break;
    }
    if (!DataCollector::IsPrintable(bytes[i]) && bytes[i] != 0x8D) {  // Allow CR ($8D)
      is_pure_string = false;
    }
  }

  if (is_pure_string) {
    // Output as string with ASC directive
    out << std::string(OPCODE_COL, ' ') << "ASC   \"";
    for (uint8_t byte : bytes) {
      if (byte == '"') {
        out << "\\\"";  // Escape quotes
      } else if (byte == '\\') {
        out << "\\\\";  // Escape backslashes
      } else if (DataCollector::IsPrintable(byte)) {
        out << static_cast<char>(byte);
      } else if (byte == 0x0D || byte == 0x0A) {
        out << "\\n";  // CR/LF as newline
      } else {
        // Shouldn't happen if is_pure_string logic is correct
        out << "?";
      }
    }
    out << "\"";
  } else {
    // Output as hex bytes with .DA directive
    out << std::string(OPCODE_COL, ' ') << ".DA   ";
    for (size_t i = 0; i < bytes.size(); ++i) {
      if (i > 0) out << ",";
      out << "$" << std::hex << std::uppercase
          << std::setw(2) << std::setfill('0')
          << static_cast<int>(bytes[i]);
    }
  }

  return out.str();
}

std::string ScmasmFormatter::FormatHeader(const core::Binary& binary) {
  std::ostringstream out;

  // Get current time with timezone
  auto now = std::chrono::system_clock::now();
  auto time_t_now = std::chrono::system_clock::to_time_t(now);
  std::tm local_tm;

#ifdef _WIN32
  localtime_s(&local_tm, &time_t_now);
#else
  localtime_r(&time_t_now, &local_tm);
#endif

  // Format: YYYY-MM-DD HH:MM:SS TZ
  char time_buf[64];
  std::strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S %Z", &local_tm);

  out << "*---------------------------------------" << std::endl;
  out << "* Sourcerer - Modern Multi-CPU Disassembler" << std::endl;
  out << "* Copyright (C) 2025 Cortexa LLC" << std::endl;
  out << "* Generated: " << time_buf << std::endl;
  out << "* Source: " << binary.source_file() << std::endl;
  out << "* Load Address: $" << FormatAddress(binary.load_address(), 4) << std::endl;
  out << "* Size: " << binary.size() << " bytes" << std::endl;
  out << "*---------------------------------------" << std::endl;
  out << std::endl;

  return out.str();
}

std::string ScmasmFormatter::FormatFooter() {
  // Don't output .TF directive - it may add extra bytes
  return "";
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
  if (auto label = address_map->GetLabel(address)) {
    return *label;
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
