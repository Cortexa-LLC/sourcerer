// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "output/merlin_formatter.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <regex>

#include "analysis/equate_generator.h"
#include "output/data_collector.h"
#include "output/address_analyzer.h"
#include "output/label_resolver.h"
#include "utils/logger.h"

namespace sourcerer {
namespace output {

std::string MerlinFormatter::Format(
    const core::Binary& binary,
    const std::vector<core::Instruction>& instructions,
    const core::AddressMap* address_map,
    const core::SymbolTable* symbol_table,
    const analysis::EquateGenerator* equate_gen) {

  std::ostringstream out;

  // Create components for this formatting session
  DataCollector data_collector(&binary);
  AddressAnalyzer address_analyzer(&binary, address_map);
  LabelResolver label_resolver(address_map, symbol_table);

  // Header
  out << FormatHeader(binary);

  // Collect all referenced addresses from instructions and data
  auto referenced_addresses = address_analyzer.CollectReferencedAddresses(instructions);

  // Output EQU statements for platform symbols that are referenced
  if (symbol_table) {
    std::set<std::string> output_symbols;  // Track to avoid duplicates
    for (uint32_t ref_addr : referenced_addresses) {
      if (auto symbol_name = symbol_table->GetSymbolName(ref_addr)) {
        if (output_symbols.find(*symbol_name) == output_symbols.end()) {
          out << *symbol_name;
          out << std::string(std::max(1, OPCODE_COL - static_cast<int>(symbol_name->length())), ' ');
          out << "EQU   $" << FormatAddress(ref_addr, 4) << std::endl;
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
        out << std::string(std::max(1, OPCODE_COL - static_cast<int>(name.length())), ' ');
        out << "EQU   $" << std::hex << std::uppercase << std::setw(2)
            << std::setfill('0') << static_cast<int>(value);

        // Add comment if available
        std::string comment = equate_gen->GetEquateComment(value);
        if (!comment.empty()) {
          int line_length = name.length() + (OPCODE_COL - name.length()) + 9;  // "EQU   $XX"
          if (line_length < COMMENT_COL) {
            out << std::string(COMMENT_COL - line_length, ' ');
            out << "; " << comment;  // Merlin uses ; for comments
          }
        }
        out << std::endl;
      }
      out << std::endl;  // Blank line after generated equates
    }
  }

  // ORG directive
  out << std::string(OPCODE_COL, ' ') << "ORG   ";
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
            out << "*-------------------------------" << std::endl;
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
        auto string_result = data_collector.CollectStringData(addr, end_addr, address_map, 128);
        data_bytes = string_result.bytes;
        addr = string_result.next_address;
      }

      // Fall back to binary data collection if string collection failed
      if (data_bytes.empty()) {
        auto binary_result = data_collector.CollectBinaryData(data_start, end_addr, address_map, 8);
        data_bytes = binary_result.bytes;
        addr = binary_result.next_address;
      }

      // Format data region (includes UNKNOWN as FCB)
      if (!data_bytes.empty()) {
        out << FormatDataRegion(data_start, data_bytes, address_map, symbol_table, &binary, &address_analyzer)
            << std::endl;
      } else {
        // Should not happen anymore since we collect UNKNOWN too
        addr++;
      }
    } else {
      // address_map says CODE but no instruction at this address
      // This can happen for orphaned CODE bytes or mid-instruction bytes
      // Output as FCB/HEX data to ensure complete coverage
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
        out << FormatDataRegion(orphan_start, orphan_bytes, nullptr, symbol_table, &binary, &address_analyzer)
            << std::endl;
      }
    }
  }

  // Footer
  out << std::endl << FormatFooter();

  return out.str();
}


// Helper: Replace address in operand with symbol name
static std::string SubstituteSymbol(const std::string& operand,
                                    uint32_t address,
                                    const std::string& symbol_name) {
  // Build address strings to try (both 2-digit and 4-digit formats)
  std::ostringstream addr_str_4;
  addr_str_4 << "$" << std::hex << std::uppercase << std::setw(4)
             << std::setfill('0') << address;

  std::ostringstream addr_str_2;
  addr_str_2 << "$" << std::hex << std::uppercase << std::setw(2)
             << std::setfill('0') << address;

  // Try to find and replace the address (try 2-digit first, then 4-digit)
  std::string result = operand;
  size_t pos = result.find(addr_str_2.str());
  if (pos != std::string::npos) {
    result.replace(pos, addr_str_2.str().length(), symbol_name);
  } else {
    pos = result.find(addr_str_4.str());
    if (pos != std::string::npos) {
      result.replace(pos, addr_str_4.str().length(), symbol_name);
    }
  }

  return result;
}

std::string MerlinFormatter::FormatInstruction(
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

    uint32_t addr = LabelResolver::ExtractAddressFromOperand(operand);

    // Priority 1: Try symbol table first (explicit user-provided symbols)
    if (!substituted && symbol_table && addr != 0xFFFFFFFF) {
      if (auto symbol_name = symbol_table->GetSymbolName(addr)) {
        operand = SubstituteSymbol(operand, addr, *symbol_name);
        substituted = true;
      }
    }

    // Priority 2: Check address map for generated labels
    // Only substitute if the address has an instruction or is at a valid boundary
    if (!substituted && address_map && addr != 0xFFFFFFFF) {
      if (auto label = address_map->GetLabel(addr)) {
        if (address_map->IsCode(addr) || address_map->IsData(addr)) {
          operand = SubstituteSymbol(operand, addr, *label);
          substituted = true;
        }
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
        out << "; " << *comment;
        has_comment = true;
      }
    }

    // Check for ROM routine description for JSR/LBSR/BSR
    if (!has_comment && inst.is_call && inst.target_address != 0 && symbol_table) {
      if (auto symbol = symbol_table->GetSymbol(inst.target_address)) {
        if (!symbol->description.empty() && symbol->type == core::SymbolType::ROM_ROUTINE) {
          out << "; " << symbol->description;
          has_comment = true;
        }
      }
    }

    if (!has_comment) {
      if (inst.is_branch) {
        // Add contextual branch comment
        std::string branch_comment = GenerateBranchComment(inst.mnemonic);
        if (!branch_comment.empty()) {
          out << "; " << branch_comment;
        }
        // No else - don't add useless address comments
      }
      // No default address comment - only meaningful comments
    }
  }

  return out.str();
}

std::string MerlinFormatter::FormatData(uint32_t address,
                                       const std::vector<uint8_t>& bytes) {
  (void)address;  // Unused parameter - may be used for labels in future
  std::ostringstream out;

  // Use DFB (Define Byte) directive for data
  out << std::string(OPCODE_COL, ' ') << "DFB   ";

  for (size_t i = 0; i < bytes.size(); ++i) {
    if (i > 0) out << ",";
    out << "$" << std::hex << std::uppercase
        << std::setw(2) << std::setfill('0')
        << static_cast<int>(bytes[i]);
  }

  return out.str();
}

// Helper: Find embedded string within data bytes
// Returns the start index of a string (at least 4 printable chars), or -1 if none found
static int FindEmbeddedString(const std::vector<uint8_t>& bytes, size_t start_offset = 0) {
  for (size_t i = start_offset; i < bytes.size(); ++i) {
    // Count consecutive printable characters from this position
    size_t printable_count = 0;
    for (size_t j = i; j < bytes.size() && printable_count < 4; ++j) {
      if (DataCollector::IsPrintable(bytes[j]) || bytes[j] == 0x8D) {  // Allow CR
        printable_count++;
      } else {
        break;
      }
    }

    // If we found at least 4 consecutive printable chars, this is likely a string
    if (printable_count >= 4) {
      return static_cast<int>(i);
    }
  }
  return -1;
}



// Helper: Check if data looks like an address table
static bool LooksLikeAddressTable(const std::vector<uint8_t>& bytes,
                                   const AddressAnalyzer* address_analyzer) {
  auto table_info = address_analyzer->FindAddressTableLengthAndOffset(bytes);
  size_t table_length = table_info.length;
  // Consider it a table if at least half the data forms valid addresses
  // and we have at least 4 bytes (2 addresses)
  if (table_length < 4 || table_length < bytes.size() / 2) {
    return false;
  }

  // Additional heuristic: If bytes form printable ASCII (with or without high bits),
  // it's likely a string, not an address table
  bool all_printable = true;
  for (size_t i = 0; i < table_length && i < bytes.size(); ++i) {
    // Allow CR ($8D) as printable for string detection
    if (!DataCollector::IsPrintable(bytes[i]) && bytes[i] != 0x8D) {
      all_printable = false;
      break;
    }
  }

  // If all bytes are printable ASCII (or CR), treat as string not address table
  if (all_printable) {
    return false;
  }

  // Check for repeated addresses - if all addresses are identical, it's likely not
  // a real address table (e.g., filler bytes like $FF,$FF,...)
  if (table_length >= 4) {
    size_t offset = table_info.offset;
    uint16_t first_addr = bytes[offset] | (bytes[offset + 1] << 8);
    bool all_same = true;
    for (size_t i = offset; i + 1 < offset + table_length; i += 2) {
      uint16_t addr = bytes[i] | (bytes[i + 1] << 8);
      if (addr != first_addr) {
        all_same = false;
        break;
      }
    }
    if (all_same) {
      return false;  // All addresses identical - not a real table
    }
  }

  return true;
}

std::string MerlinFormatter::FormatDataRegion(
    uint32_t address,
    const std::vector<uint8_t>& bytes,
    const core::AddressMap* address_map,
    const core::SymbolTable* symbol_table,
    const core::Binary* binary,
    const AddressAnalyzer* address_analyzer) {

  std::ostringstream out;

  // Add label if this address has one
  if (address_map) {
    if (auto label = address_map->GetLabel(address)) {
      out << *label;
      if (label->length() < OPCODE_COL) {
        out << std::string(OPCODE_COL - label->length(), ' ');
      } else {
        // Label too long - put directive on next line
        out << std::endl << std::string(OPCODE_COL, ' ');
      }
    } else {
      out << std::string(OPCODE_COL, ' ');
    }
  } else {
    out << std::string(OPCODE_COL, ' ');
  }

  // Check if this is inline data (like ProDOS MLI parameters)
  bool is_inline_data = false;
  if (address_map) {
    core::AddressType type = address_map->GetType(address);
    is_inline_data = (type == core::AddressType::INLINE_DATA);
  }

  // For inline data, always use HEX or DFB format, never ASC
  // Detect data type: Check for address tables FIRST (more specific), then strings, then raw hex

  // Check for address table first (but not for inline data)
  bool is_address_table = !is_inline_data && address_analyzer && LooksLikeAddressTable(bytes, address_analyzer);

  // Check for string: either all bytes are printable, OR there's an embedded string
  bool is_pure_string = !is_inline_data && !is_address_table && bytes.size() >= 3;
  bool has_high_bit = false;
  for (size_t i = 0; i < bytes.size() && is_pure_string; ++i) {
    // CRITICAL: Reject high-bit bytes (graphics data, not ASCII), except CR ($8D)
    if (bytes[i] >= 0x80 && bytes[i] != 0x8D) {
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
    if ((bytes[i] & 0x80) != 0) {
      has_high_bit = true;
    }
  }

  // Check for embedded string if not a pure string
  int embedded_string_pos = -1;
  if (!is_inline_data && !is_address_table && !is_pure_string) {
    embedded_string_pos = FindEmbeddedString(bytes);
  }

  // Handle embedded string by splitting the output
  if (embedded_string_pos > 0) {
    // Output non-string prefix as HEX
    out << "HEX   ";
    for (int i = 0; i < embedded_string_pos; ++i) {
      if (i > 0 && i % 8 == 0) {
        // Max 8 bytes per line
        out << std::endl << std::string(OPCODE_COL, ' ') << "HEX   ";
      }
      if (i > 0) out << ",";
      out << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
          << static_cast<int>(bytes[i]);
    }

    // Now format the string portion recursively
    std::vector<uint8_t> string_bytes(bytes.begin() + embedded_string_pos, bytes.end());
    out << std::endl;
    out << FormatDataRegion(address + embedded_string_pos, string_bytes, address_map, symbol_table, binary, address_analyzer);
    // Note: This recursive call will format the string and any remaining data
    return out.str();
  }

  if (is_pure_string) {
    // Choose delimiter based on high bit status
    // Delimiter < 0x27 (like ") → high bit SET (negative ASCII)
    // Delimiter >= 0x27 (like ') → high bit CLEAR (positive ASCII)
    char delimiter = has_high_bit ? '"' : '\'';

    // Format as ASCII string
    out << "ASC   " << delimiter;
    for (size_t i = 0; i < bytes.size(); ++i) {
      uint8_t byte = bytes[i];
      if (byte == 0x00) break;  // Null terminator

      if (byte == 0x8D) {
        // Carriage return - close string and output as HEX
        if (i > 0) out << delimiter;
        out << std::endl << std::string(OPCODE_COL, ' ') << "HEX   8D";
        if (i + 1 < bytes.size()) {
          out << std::endl << std::string(OPCODE_COL, ' ') << "ASC   " << delimiter;
        }
      } else {
        char ch = static_cast<char>(byte & 0x7F);  // Strip high bit for display
        if (ch == delimiter) {
          // Can't escape in Merlin - need to switch delimiters or use HEX
          // For simplicity, close string, output byte as HEX, reopen string
          out << delimiter;
          out << std::endl << std::string(OPCODE_COL, ' ') << "HEX   ";
          out << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
              << static_cast<int>(byte);
          if (i + 1 < bytes.size()) {
            out << std::endl << std::string(OPCODE_COL, ' ') << "ASC   " << delimiter;
          }
        } else {
          out << ch;
        }
      }
    }
    out << delimiter;
  } else if (is_address_table) {
    // Format as address table using DA (Define Address) directive
    // Find the actual length of consecutive valid addresses and offset
    auto table_info = address_analyzer->FindAddressTableLengthAndOffset(bytes);
    size_t table_length = table_info.length;
    size_t table_offset = table_info.offset;

    // If table starts at offset 1, output the first byte separately
    if (table_offset == 1 && bytes.size() > 0) {
      out << "HEX   " << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
          << static_cast<int>(bytes[0]);
      out << std::endl;

      // Recursively format the rest starting from offset 1
      if (bytes.size() > 1) {
        std::vector<uint8_t> remaining(bytes.begin() + 1, bytes.end());
        out << FormatDataRegion(address + 1, remaining, nullptr, symbol_table, binary, address_analyzer);
      }
      return out.str();
    }

    if (table_length > 0 && table_length <= bytes.size()) {
      // Format the address table portion
      out << "DA    ";
      for (size_t i = 0; i < table_length; i += 2) {
        if (i > 0) {
          if (i % 16 == 0) {
            // Max 8 addresses per line
            out << std::endl << std::string(OPCODE_COL, ' ') << "DA    ";
          } else {
            out << ",";
          }
        }
        uint16_t addr = bytes[i] | (bytes[i + 1] << 8);

        // Try to substitute with symbol name
        bool found_symbol = false;

        // Priority 1: Try symbol table first
        if (symbol_table) {
          if (auto symbol_name = symbol_table->GetSymbolName(addr)) {
            out << *symbol_name;
            found_symbol = true;
          }
        }

        // Priority 2: Check address map for labels
        // Only substitute if the address has an instruction or is at a valid boundary
        if (!found_symbol && address_map) {
          if (auto label = address_map->GetLabel(addr)) {
            // Verify the address is at a valid code/data boundary
            if (address_map->IsCode(addr) || address_map->IsData(addr)) {
              out << *label;
              found_symbol = true;
            }
          }
        }

        // Default: output as hex address
        if (!found_symbol) {
          out << "$" << std::hex << std::uppercase << std::setw(4)
              << std::setfill('0') << addr;
        }
      }

      // If there are bytes left over after the table, format them as HEX on next line
      if (table_length < bytes.size()) {
        out << std::endl << std::string(OPCODE_COL, ' ') << "HEX   ";
        for (size_t i = table_length; i < bytes.size(); ++i) {
          if (i > table_length) {
            if ((i - table_length) % 8 == 0) {
              out << std::endl << std::string(OPCODE_COL, ' ') << "HEX   ";
            } else {
              out << ",";
            }
          }
          out << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
              << static_cast<int>(bytes[i]);
        }
        // No address comment - keep output clean
      }
    } else {
      // Shouldn't happen, but fall back to HEX if table_length is invalid
      out << "HEX   ";
      for (size_t i = 0; i < bytes.size(); ++i) {
        if (i > 0) {
          if (i % 8 == 0) {
            out << std::endl << std::string(OPCODE_COL, ' ') << "HEX   ";
          } else {
            out << ",";
          }
        }
        out << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
            << static_cast<int>(bytes[i]);
      }
    }
  } else {
    // Format as hex bytes (8 per line max)
    out << "HEX   ";
    for (size_t i = 0; i < bytes.size(); ++i) {
      if (i > 0) {
        if (i % 8 == 0) {
          out << std::endl << std::string(OPCODE_COL, ' ') << "HEX   ";
        } else {
          out << ",";
        }
      }
      out << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
          << static_cast<int>(bytes[i]);
    }
  }

  // No address comment - keep output clean

  return out.str();
}

std::string MerlinFormatter::FormatHeader(const core::Binary& binary) {
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

  out << "*" << std::string(39, '-') << std::endl;
  out << "* Sourcerer - Multi-CPU Disassembler" << std::endl;
  out << "* Copyright (C) 2025 Cortexa LLC" << std::endl;
  out << "* Generated: " << time_buf << std::endl;
  out << "* Disassembly of: " << binary.source_file() << std::endl;
  out << "* Load address: $" << FormatAddress(binary.load_address(), 4) << std::endl;
  out << "* Size: " << binary.size() << " bytes" << std::endl;
  if (!binary.file_type().empty()) {
    out << "* File type: " << binary.file_type() << std::endl;
  }
  out << "*" << std::string(39, '-') << std::endl;

  return out.str();
}

std::string MerlinFormatter::FormatFooter() {
  // Don't output CHK directive - it may add extra bytes
  return "";
}

std::string MerlinFormatter::FormatAddress(uint32_t address, int width) const {
  std::ostringstream out;
  out << std::hex << std::uppercase << std::setw(width) 
      << std::setfill('0') << address;
  return out.str();
}

std::string MerlinFormatter::GetLabel(uint32_t address,
                                      const core::AddressMap* address_map) const {
  if (address_map) {
    if (auto label = address_map->GetLabel(address)) {
      return *label;
    }
  }
  return "";
}

bool MerlinFormatter::IsSubroutineLabel(const std::string& label) const {
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

std::string MerlinFormatter::GenerateBranchComment(const std::string& mnemonic) const {
  // Generate contextual comments for branch instructions
  // Merlin uses semicolon prefix

  if (mnemonic == "BCS") return "Carry set";
  if (mnemonic == "BCC") return "Carry clear";
  if (mnemonic == "BEQ") return "Equal / zero";
  if (mnemonic == "BNE") return "Not equal / not zero";
  if (mnemonic == "BMI") return "Minus / negative";
  if (mnemonic == "BPL") return "Plus / positive";
  if (mnemonic == "BVS") return "Overflow set";
  if (mnemonic == "BVC") return "Overflow clear";
  if (mnemonic == "BRA") return "Always";  // 65C02

  return "";  // No comment for non-branch instructions
}

std::unique_ptr<Formatter> CreateMerlinFormatter() {
  return std::make_unique<MerlinFormatter>();
}

}  // namespace output
}  // namespace sourcerer
