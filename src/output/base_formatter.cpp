// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "output/base_formatter.h"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>

#include "analysis/equate_generator.h"
#include "output/address_analyzer.h"
#include "output/data_collector.h"
#include "output/label_resolver.h"
#include "utils/logger.h"

namespace sourcerer {
namespace output {

BaseFormatter::BaseFormatter() = default;

BaseFormatter::~BaseFormatter() = default;

std::string BaseFormatter::Format(
    const core::Binary& binary,
    const std::vector<core::Instruction>& instructions,
    const core::AddressMap* address_map,
    const core::SymbolTable* symbol_table,
    const analysis::EquateGenerator* equate_gen) {

  std::ostringstream out;

  // Create components for this formatting session
  data_collector_ = std::make_unique<DataCollector>(&binary);
  address_analyzer_ = std::make_unique<AddressAnalyzer>(&binary, address_map);
  label_resolver_ = std::make_unique<LabelResolver>(address_map, symbol_table);

  // Header
  out << FormatHeader(binary);

  // Collect all referenced addresses from instructions
  auto referenced_addresses = address_analyzer_->CollectReferencedAddresses(instructions);

  // Output EQU statements
  out << FormatEquates(referenced_addresses, symbol_table, equate_gen);

  // ORG directive
  out << std::string(GetOpcodeColumn(), ' ') << GetOrgDirective() << "   ";
  out << "$" << FormatAddress(binary.load_address(), 4);
  out << std::endl << std::endl;

  // Build instruction map for quick lookup
  std::map<uint32_t, core::Instruction> inst_map;
  for (const auto& inst : instructions) {
    inst_map[inst.address] = inst;
  }

  // Walk through binary in address order (CODE/DATA interleaving)
  uint32_t address = binary.load_address();
  uint32_t end_address = address + binary.size();

  while (address < end_address) {
    // Check if we have an instruction at this address
    auto it = inst_map.find(address);

    if (it != inst_map.end()) {
      // Output the instruction
      const core::Instruction& inst = it->second;
      out << FormatInstruction(inst, address_map, symbol_table, equate_gen);
      out << std::endl;
      address += inst.bytes.size();
    } else if (address_map && address_map->GetType(address) != core::AddressType::CODE) {
      // Data region - collect contiguous DATA/UNKNOWN bytes
      uint32_t data_start = address;
      std::vector<uint8_t> data_bytes;

      while (address < end_address &&
             inst_map.find(address) == inst_map.end() &&
             address_map->GetType(address) != core::AddressType::CODE &&
             data_bytes.size() < 16) {  // Limit to 16 bytes per line
        if (const uint8_t* byte = binary.GetPointer(address)) {
          data_bytes.push_back(*byte);
        }
        address++;
      }

      if (!data_bytes.empty()) {
        out << FormatDataRegion(data_start, data_bytes, address_map, symbol_table, &binary);
        out << std::endl;
      }
    } else {
      // CODE byte without instruction (orphan) or no address_map
      // Output as data
      if (const uint8_t* byte = binary.GetPointer(address)) {
        std::vector<uint8_t> data_byte = {*byte};
        out << FormatDataRegion(address, data_byte, address_map, symbol_table, &binary);
        out << std::endl;
      }
      address++;
    }
  }

  // Footer
  out << FormatFooter();

  // Optional: Add line numbers (SCMASM only)
  std::string result = out.str();
  if (RequiresLineNumbers()) {
    result = AddLineNumbers(result);
  }

  return result;
}

std::string BaseFormatter::FormatInstruction(
    const core::Instruction& inst,
    const core::AddressMap* address_map,
    const core::SymbolTable* symbol_table,
    const analysis::EquateGenerator* /* equate_gen */) {

  std::ostringstream out;

  // Get label for this address
  std::string label = GetLabel(inst.address, address_map);

  // Add blank line before subroutine labels
  if (!label.empty() && IsSubroutineLabel(label)) {
    out << std::endl;
  }

  // Output label (left-aligned)
  if (!label.empty()) {
    out << label;
    out << std::string(std::max(1, GetOpcodeColumn() - static_cast<int>(label.length())), ' ');
  } else {
    out << std::string(GetOpcodeColumn(), ' ');
  }

  // Output mnemonic
  out << inst.mnemonic;

  // Output operand if present
  if (!inst.operand.empty()) {
    int operand_col = GetOperandColumn();
    int current_col = GetOpcodeColumn() + inst.mnemonic.length();
    out << std::string(std::max(1, operand_col - current_col), ' ');

    // Substitute labels in operand if possible
    std::string operand = inst.operand;
    if (address_map || symbol_table) {
      LabelResolver resolver(address_map, symbol_table);
      auto result = resolver.SubstituteLabel(inst.operand);
      if (result.substituted) {
        operand = result.operand;
      }
    }

    out << operand;
  }

  // Generate comment
  int line_length = GetOpcodeColumn() + inst.mnemonic.length();
  if (!inst.operand.empty()) {
    line_length = GetOperandColumn() + inst.operand.length();
  }

  if (line_length < GetCommentColumn()) {
    std::string comment = GenerateInstructionComment(inst, address_map, symbol_table);

    if (!comment.empty()) {
      out << std::string(GetCommentColumn() - line_length, ' ');
      out << GetCommentPrefix();
      WriteMultiLineComment(out, comment, GetCommentColumn());
    }
  }

  return out.str();
}

std::string BaseFormatter::FormatData(uint32_t address,
                                     const std::vector<uint8_t>& bytes) {
  (void)address;
  std::ostringstream out;

  // Use byte directive (FCB/DFB/.DA)
  out << std::string(GetOpcodeColumn(), ' ') << GetByteDirective() << "   ";

  for (size_t i = 0; i < bytes.size(); ++i) {
    if (i > 0) out << ",";
    out << "$" << std::hex << std::uppercase
        << std::setw(2) << std::setfill('0')
        << static_cast<int>(bytes[i]);
  }

  return out.str();
}

std::string BaseFormatter::FormatHeader(const core::Binary& binary) {
  std::ostringstream out;

  // Get current time
  auto now = std::chrono::system_clock::now();
  auto time_t_now = std::chrono::system_clock::to_time_t(now);
  std::tm local_tm;

#ifdef _WIN32
  localtime_s(&local_tm, &time_t_now);
#else
  localtime_r(&time_t_now, &local_tm);
#endif

  char time_buf[64];
  std::strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S %Z", &local_tm);

  std::string comment_prefix = GetCommentPrefix();
  if (comment_prefix.empty()) {
    comment_prefix = "* ";  // Fallback for formats without comment prefix
  }

  out << comment_prefix << std::string(38, '-') << std::endl;
  out << comment_prefix << "Sourcerer - Multi-CPU Disassembler" << std::endl;
  out << comment_prefix << "Copyright (C) 2025 Cortexa LLC" << std::endl;
  out << comment_prefix << "Generated: " << time_buf << std::endl;
  out << comment_prefix << "Source: " << binary.source_file() << std::endl;
  out << comment_prefix << "Load Address: $" << FormatAddress(binary.load_address(), 4) << std::endl;
  out << comment_prefix << "Size: " << std::dec << binary.size() << " bytes" << std::endl;
  out << comment_prefix << std::string(38, '-') << std::endl;
  out << std::endl;

  // Allow subclasses to add custom header content
  out << FormatHeaderContent(binary);

  return out.str();
}

std::string BaseFormatter::FormatFooter() {
  std::ostringstream out;

  // Allow subclasses to add custom footer content
  out << FormatFooterContent();

  // END directive (if any)
  std::string end_directive = GetEndDirective();
  if (!end_directive.empty()) {
    out << std::string(GetOpcodeColumn(), ' ') << end_directive << std::endl;
  }

  return out.str();
}

// Hook methods - default implementations

std::string BaseFormatter::FormatHeaderContent(const core::Binary& binary) {
  (void)binary;
  return "";  // Subclasses can override
}

std::string BaseFormatter::FormatFooterContent() {
  return "";  // Subclasses can override
}

std::string BaseFormatter::AddLineNumbers(const std::string& text) const {
  // Default: no line numbers (SCMASM overrides this)
  return text;
}

std::string BaseFormatter::FormatDataRegionCustom(
    uint32_t address,
    const std::vector<uint8_t>& bytes,
    const core::AddressMap* address_map,
    const core::SymbolTable* symbol_table,
    const core::Binary* binary) {
  (void)address;
  (void)bytes;
  (void)address_map;
  (void)symbol_table;
  (void)binary;
  return "";  // Subclasses can override for format-specific data handling
}

std::string BaseFormatter::GenerateBranchCommentCustom(
    const std::string& mnemonic) const {
  (void)mnemonic;
  return "";  // Subclasses can override
}

std::string BaseFormatter::GenerateSemanticCommentCustom(
    const core::Instruction& inst,
    const core::SymbolTable* symbol_table) const {
  (void)inst;
  (void)symbol_table;
  return "";  // Subclasses can override
}

// Private helper implementations

std::string BaseFormatter::FormatEquates(
    const std::set<uint32_t>& referenced_addresses,
    const core::SymbolTable* symbol_table,
    const analysis::EquateGenerator* equate_gen) {

  std::ostringstream out;

  // Output EQU statements for platform symbols that are referenced
  if (symbol_table) {
    std::set<std::string> output_symbols;  // Track to avoid duplicates
    for (uint32_t ref_addr : referenced_addresses) {
      if (auto symbol_name = symbol_table->GetSymbolName(ref_addr)) {
        if (output_symbols.find(*symbol_name) == output_symbols.end()) {
          out << *symbol_name;
          out << std::string(std::max(1, GetOpcodeColumn() - static_cast<int>(symbol_name->length())), ' ');
          out << GetEquateDirective() << "   $" << FormatAddress(ref_addr, 4) << std::endl;
          output_symbols.insert(*symbol_name);
        }
      }
    }
    if (!output_symbols.empty()) {
      out << std::endl;  // Blank line after platform symbols
    }
  }

  // Output EQU statements for generated equates
  if (equate_gen) {
    const auto& equates = equate_gen->GetEquates();
    if (!equates.empty()) {
      for (const auto& pair : equates) {
        uint8_t value = pair.first;
        const std::string& name = pair.second;
        out << name;
        out << std::string(std::max(1, GetOpcodeColumn() - static_cast<int>(name.length())), ' ');
        out << GetEquateDirective() << "   $" << std::hex << std::uppercase << std::setw(2)
            << std::setfill('0') << static_cast<int>(value);

        // Add comment if available
        std::string comment = equate_gen->GetEquateComment(value);
        if (!comment.empty()) {
          int line_length = name.length() + (GetOpcodeColumn() - name.length()) + 9;  // "EQU   $XX"
          if (line_length < GetCommentColumn()) {
            out << std::string(GetCommentColumn() - line_length, ' ');
            out << GetCommentPrefix();
            WriteMultiLineComment(out, comment, GetCommentColumn());
          }
        }
        out << std::endl;
      }
      out << std::endl;  // Blank line after generated equates
    }
  }

  return out.str();
}

void BaseFormatter::WriteMultiLineComment(std::ostream& out,
                                          const std::string& comment,
                                          int indent_column) const {
  // Split comment on newlines
  std::istringstream iss(comment);
  std::string line;
  bool first_line = true;

  while (std::getline(iss, line)) {
    if (!first_line) {
      // For subsequent lines, start a new line and indent
      out << std::endl;
      out << std::string(indent_column, ' ');
      out << GetCommentPrefix();
    }
    out << line;
    first_line = false;
  }
}

std::string BaseFormatter::FormatAddress(uint32_t address, int width) const {
  std::ostringstream out;
  out << std::hex << std::uppercase
      << std::setw(width) << std::setfill('0')
      << address;
  return out.str();
}

std::string BaseFormatter::GetLabel(uint32_t address,
                                   const core::AddressMap* address_map) const {
  if (!address_map) {
    return "";
  }

  if (auto label = address_map->GetLabel(address)) {
    return *label;
  }

  return "";
}

bool BaseFormatter::IsSubroutineLabel(const std::string& label) const {
  // Convention: labels starting with "SUB" or "FN" or "FUNC" are subroutines
  return label.find("SUB") == 0 || label.find("FN") == 0 || label.find("FUNC") == 0;
}

std::string BaseFormatter::FormatDataRegion(
    uint32_t address,
    const std::vector<uint8_t>& bytes,
    const core::AddressMap* address_map,
    const core::SymbolTable* symbol_table,
    const core::Binary* binary) {

  // Allow subclass customization first
  std::string custom = FormatDataRegionCustom(address, bytes, address_map, symbol_table, binary);
  if (!custom.empty()) {
    return custom;
  }

  // Default data formatting
  std::ostringstream out;
  const uint8_t* data = bytes.data();
  size_t size = bytes.size();
  uint32_t current_address = address;

  while (size > 0) {
    // Add label if present
    std::string label = GetLabel(current_address, address_map);
    if (!label.empty()) {
      if (current_address > address) {
        out << std::endl;  // Blank line before new labeled section
      }
      out << label << std::endl;
    }

    // Check if this looks like string data
    if (IsStringData(data, size)) {
      size_t string_len = 0;
      while (string_len < size && data[string_len] >= 0x20 && data[string_len] <= 0x7E) {
        string_len++;
      }
      out << FormatStringData(current_address, data, string_len, address_map);
      out << std::endl;
      data += string_len;
      current_address += string_len;
      size -= string_len;
    } else {
      // Binary data - output up to 8 bytes per line
      size_t chunk_size = std::min(size, static_cast<size_t>(8));
      std::vector<uint8_t> chunk(data, data + chunk_size);
      out << FormatData(current_address, chunk);

      // Add comment if available for this address
      if (address_map) {
        if (auto comment = address_map->GetComment(current_address)) {
          int line_length = GetOpcodeColumn() + GetByteDirective().length() + 3;
          line_length += chunk.size() * 3 + (chunk.size() - 1);  // "$XX" per byte + commas
          if (line_length < GetCommentColumn()) {
            out << std::string(GetCommentColumn() - line_length, ' ');
            out << GetCommentPrefix();
            WriteMultiLineComment(out, *comment, GetCommentColumn());
          }
        }
      }

      out << std::endl;
      data += chunk_size;
      current_address += chunk_size;
      size -= chunk_size;
    }
  }

  return out.str();
}

bool BaseFormatter::IsStringData(const uint8_t* data, size_t size) const {
  if (size < 4) return false;

  // Check if at least 4 consecutive printable ASCII characters
  int printable_count = 0;
  for (size_t i = 0; i < std::min(size, static_cast<size_t>(8)); ++i) {
    if (data[i] >= 0x20 && data[i] <= 0x7E) {
      printable_count++;
    } else {
      break;
    }
  }

  return printable_count >= 4;
}

std::string BaseFormatter::FormatStringData(
    uint32_t address,
    const uint8_t* data,
    size_t size,
    const core::AddressMap* address_map) const {

  (void)address;
  (void)address_map;

  std::ostringstream out;
  out << std::string(GetOpcodeColumn(), ' ') << GetStringDirective() << "   \"";

  for (size_t i = 0; i < size; ++i) {
    char ch = static_cast<char>(data[i]);
    if (ch == '"') {
      out << "\\\"";  // Escape quotes
    } else if (ch == '\\') {
      out << "\\\\";  // Escape backslashes
    } else {
      out << ch;
    }
  }

  out << "\"";
  return out.str();
}

std::string BaseFormatter::FormatBinaryData(
    uint32_t address,
    const uint8_t* data,
    size_t size,
    const core::AddressMap* address_map) const {

  (void)address;
  (void)address_map;

  std::ostringstream out;
  out << std::string(GetOpcodeColumn(), ' ') << GetByteDirective() << "   ";

  for (size_t i = 0; i < size; ++i) {
    if (i > 0) out << ",";
    out << "$" << std::hex << std::uppercase
        << std::setw(2) << std::setfill('0')
        << static_cast<int>(data[i]);
  }

  return out.str();
}

std::string BaseFormatter::FormatWordData(
    uint32_t address,
    const uint8_t* data,
    size_t size,
    const core::AddressMap* address_map) const {

  (void)address;
  (void)address_map;

  std::ostringstream out;
  out << std::string(GetOpcodeColumn(), ' ') << GetWordDirective() << "   ";

  for (size_t i = 0; i < size; i += 2) {
    if (i > 0) out << ",";
    if (i + 1 < size) {
      uint16_t word = (data[i] << 8) | data[i + 1];
      out << "$" << std::hex << std::uppercase
          << std::setw(4) << std::setfill('0')
          << word;
    } else {
      // Odd byte at end
      out << "$" << std::hex << std::uppercase
          << std::setw(2) << std::setfill('0')
          << static_cast<int>(data[i]);
    }
  }

  return out.str();
}

std::string BaseFormatter::GenerateInstructionComment(
    const core::Instruction& inst,
    const core::AddressMap* address_map,
    const core::SymbolTable* symbol_table) const {

  std::string comment;

  // Priority 1: User-provided comment from address map
  if (address_map) {
    if (auto addr_comment = address_map->GetComment(inst.address)) {
      comment = *addr_comment;
    }
  }

  // Priority 2: ROM routine description for JSR/LBSR/BSR
  if (comment.empty() && inst.is_call && inst.target_address != 0 && symbol_table) {
    if (auto symbol = symbol_table->GetSymbol(inst.target_address)) {
      if (!symbol->description.empty() && symbol->type == core::SymbolType::ROM_ROUTINE) {
        comment = symbol->description;
      }
    }
  }

  // Priority 3: Branch instruction comments
  if (comment.empty() && inst.is_branch) {
    comment = GenerateBranchComment(inst.mnemonic);
    // Allow subclass customization
    std::string custom = GenerateBranchCommentCustom(inst.mnemonic);
    if (!custom.empty()) {
      comment = custom;
    }
  }

  // Priority 4: Semantic comments
  if (comment.empty()) {
    comment = GenerateSemanticComment(inst, symbol_table);
    // Allow subclass customization
    std::string custom = GenerateSemanticCommentCustom(inst, symbol_table);
    if (!custom.empty()) {
      comment = custom;
    }
  }

  // No fallback to address comments - only show meaningful comments

  return comment;
}

std::string BaseFormatter::GenerateBranchComment(const std::string& mnemonic) const {
  // Generic branch comments
  if (mnemonic == "BEQ" || mnemonic == "BNE" ||
      mnemonic == "BCS" || mnemonic == "BCC" ||
      mnemonic == "BMI" || mnemonic == "BPL" ||
      mnemonic == "BVS" || mnemonic == "BVC") {
    return "Branch based on flags";
  }
  return "";
}

std::string BaseFormatter::GenerateSemanticComment(
    const core::Instruction& inst,
    const core::SymbolTable* symbol_table) const {

  // Stack operations
  if (inst.mnemonic == "PSHS" || inst.mnemonic == "PHA") {
    return "Push to stack";
  }
  if (inst.mnemonic == "PULS" || inst.mnemonic == "PLA") {
    return "Pull from stack";
  }

  // Platform hints for operands
  if (symbol_table && !inst.operand.empty()) {
    std::string hint = GetPlatformHint(inst.operand, symbol_table);
    if (!hint.empty()) {
      return hint;
    }
  }

  return "";
}

std::string BaseFormatter::GetPlatformHint(
    const std::string& operand,
    const core::SymbolTable* symbol_table) const {

  if (!symbol_table) {
    return "";
  }

  // Extract address from operand (e.g., "$FF00" -> 0xFF00)
  if (operand.find('$') != std::string::npos) {
    try {
      size_t pos = operand.find('$');
      std::string hex_str = operand.substr(pos + 1);
      uint32_t addr = std::stoul(hex_str, nullptr, 16);

      if (auto symbol = symbol_table->GetSymbol(addr)) {
        if (!symbol->description.empty()) {
          return symbol->description;
        }
      }
    } catch (const std::exception&) {
      // Parse error - ignore and return empty string
    }
  }

  return "";
}

bool BaseFormatter::IsPlatformRegister(const std::string& symbol) const {
  // Common platform register patterns
  return symbol.find("PIA") == 0 ||
         symbol.find("VIA") == 0 ||
         symbol.find("ACIA") == 0 ||
         symbol.find("SAM") == 0 ||
         symbol.find("GIME") == 0;
}

}  // namespace output
}  // namespace sourcerer
