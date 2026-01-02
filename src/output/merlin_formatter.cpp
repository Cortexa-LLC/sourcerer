// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "output/merlin_formatter.h"

#include <iomanip>
#include <sstream>
#include <regex>

#include "analysis/equate_generator.h"
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

  // Header
  out << FormatHeader(binary);

  // Collect all referenced addresses from instructions and data
  std::set<uint32_t> referenced_addresses;
  for (const auto& inst : instructions) {
    if (inst.target_address != 0) {
      referenced_addresses.insert(inst.target_address);
    }
  }

  // Scan data regions for address tables
  uint32_t scan_addr = binary.load_address();
  uint32_t scan_end = scan_addr + binary.size();
  while (scan_addr < scan_end) {
    if (address_map && address_map->GetType(scan_addr) == core::AddressType::DATA) {
      // Check if this looks like an address pair
      const uint8_t* lo = binary.GetPointer(scan_addr);
      const uint8_t* hi = binary.GetPointer(scan_addr + 1);
      if (lo && hi) {
        uint16_t potential_addr = (*lo) | ((*hi) << 8);
        // If it looks like a valid address, add it
        if (potential_addr >= 0x0800 || potential_addr < 0x0100) {
          referenced_addresses.insert(potential_addr);
        }
      }
      scan_addr++;
    } else {
      scan_addr++;
    }
  }

  // Output EQU statements for platform symbols that are referenced
  if (symbol_table) {
    std::set<std::string> output_symbols;  // Track to avoid duplicates
    for (uint32_t ref_addr : referenced_addresses) {
      if (symbol_table->HasSymbol(ref_addr)) {
        std::string symbol_name = symbol_table->GetSymbolName(ref_addr);
        if (output_symbols.find(symbol_name) == output_symbols.end()) {
          out << symbol_name;
          out << std::string(std::max(1, OPCODE_COL - static_cast<int>(symbol_name.length())), ' ');
          out << "EQU   $" << FormatAddress(ref_addr, 4) << std::endl;
          output_symbols.insert(symbol_name);
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
      if (address_map && address_map->HasLabel(addr)) {
        std::string label = address_map->GetLabel(addr);
        if (IsSubroutineLabel(label)) {
          out << "*-------------------------------" << std::endl;
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
      bool looks_like_string = false;
      if (addr + 3 < end_addr && address_map) {
        int printable_count = 0;
        for (int i = 0; i < 4 && addr + i < end_addr; ++i) {
          const uint8_t* byte = binary.GetPointer(addr + i);
          if (byte && ((*byte & 0x7F) >= 0x20 && (*byte & 0x7F) < 0x7F)) {
            printable_count++;
          }
        }
        looks_like_string = (printable_count >= 3);
      }

      if (looks_like_string && address_map) {
        // Collect string data
        while (addr < end_addr &&
               address_map->GetType(addr) != core::AddressType::CODE &&
               address_map->GetType(addr) != core::AddressType::UNKNOWN) {
          const uint8_t* byte = binary.GetPointer(addr);
          if (!byte) break;

          uint8_t b = *byte;
          // Stop at null terminator (don't include it in the string)
          if (b == 0x00) {
            addr++;  // Skip the null terminator
            break;
          }
          // Stop if not printable (except CR)
          if (!((b & 0x7F) >= 0x20 && (b & 0x7F) < 0x7F) && b != 0x8D) {
            break;
          }

          data_bytes.push_back(b);
          addr++;

          // Limit string length
          if (data_bytes.size() >= 128) break;
        }
      } else {
        // Collect binary data (max 8 bytes)
        while (addr < end_addr &&
               (!address_map ||
                (address_map->GetType(addr) != core::AddressType::CODE &&
                 address_map->GetType(addr) != core::AddressType::UNKNOWN)) &&
               data_bytes.size() < 8) {
          const uint8_t* byte = binary.GetPointer(addr);
          if (byte) {
            data_bytes.push_back(*byte);
          }
          addr++;
        }
      }

      // Format data region
      if (!data_bytes.empty()) {
        out << FormatDataRegion(data_start, data_bytes, address_map, symbol_table, &binary)
            << std::endl;
      } else {
        // No data collected (e.g., UNKNOWN type), skip this byte
        addr++;
      }
    } else {
      // address_map says CODE but no instruction - skip this byte
      addr++;
    }
  }

  // Footer
  out << std::endl << FormatFooter();

  return out.str();
}

// Helper: Extract address from operand string
// Handles formats like "$C000", "#$FF", "($FDED)", "($40),Y", etc.
static uint32_t ExtractAddressFromOperand(const std::string& operand) {
  // Use regex to find hex addresses in various formats
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

    uint32_t addr = ExtractAddressFromOperand(operand);

    // Priority 1: Try symbol table first (explicit user-provided symbols)
    if (!substituted && symbol_table && addr != 0xFFFFFFFF) {
      if (symbol_table->HasSymbol(addr)) {
        operand = SubstituteSymbol(operand, addr,
                                    symbol_table->GetSymbolName(addr));
        substituted = true;
      }
    }

    // Priority 2: Check address map for generated labels
    if (!substituted && address_map && addr != 0xFFFFFFFF) {
      if (address_map->HasLabel(addr)) {
        operand = SubstituteSymbol(operand, addr,
                                    address_map->GetLabel(addr));
        substituted = true;
      }
    }

    // Priority 3: For branch/jump instructions, use target_address from address_map
    if (!substituted && address_map && inst.target_address != 0) {
      if (address_map->HasLabel(inst.target_address)) {
        operand = address_map->GetLabel(inst.target_address);
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
    if (address_map && address_map->HasComment(inst.address)) {
      out << "; " << address_map->GetComment(inst.address);
    } else if (inst.is_branch) {
      // Add contextual branch comment
      std::string branch_comment = GenerateBranchComment(inst.mnemonic);
      if (!branch_comment.empty()) {
        out << "; " << branch_comment;
      } else {
        out << "; $" << FormatAddress(inst.address, 4);
      }
    } else {
      // Default comment shows address
      out << "; $" << FormatAddress(inst.address, 4);
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

// Helper: Check if byte is printable ASCII (including high-bit set)
static bool IsPrintable(uint8_t byte) {
  uint8_t low = byte & 0x7F;  // Strip high bit
  return low >= 0x20 && low < 0x7F;
}

// Helper: Find embedded string within data bytes
// Returns the start index of a string (at least 4 printable chars), or -1 if none found
static int FindEmbeddedString(const std::vector<uint8_t>& bytes, size_t start_offset = 0) {
  for (size_t i = start_offset; i < bytes.size(); ++i) {
    // Count consecutive printable characters from this position
    size_t printable_count = 0;
    for (size_t j = i; j < bytes.size() && printable_count < 4; ++j) {
      if (IsPrintable(bytes[j]) || bytes[j] == 0x8D) {  // Allow CR
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

// Helper: Check if a single 16-bit value looks like an address
static bool LooksLikeAddress(uint16_t addr,
                              const core::AddressMap* address_map = nullptr,
                              const core::Binary* binary = nullptr) {
  // Priority 1: If we have address_map, check if this address points to CODE or has a label
  if (address_map) {
    if (address_map->IsCode(addr) || address_map->HasLabel(addr)) {
      return true;
    }
  }

  // Priority 2: If we have binary info, check if address is within binary range
  if (binary && binary->IsValidAddress(addr)) {
    return true;
  }

  // Priority 3: Check if address is in common ranges
  // Zero page: $0000-$00FF
  // User RAM: $0800-$BFFF (Apple II)
  // ROM: $C000-$FFFF
  return (addr < 0x0100 || (addr >= 0x0800 && addr <= 0xBFFF) || addr >= 0xC000);
}

// Helper: Find how many consecutive address pairs we have
// Returns the number of bytes that form a valid address table (must be even)
static size_t FindAddressTableLength(const std::vector<uint8_t>& bytes,
                                      const core::AddressMap* address_map = nullptr,
                                      const core::Binary* binary = nullptr) {
  if (bytes.size() < 4) {
    return 0;  // Need at least 2 addresses (4 bytes)
  }

  size_t valid_length = 0;

  // Check each pair of bytes as a potential address
  for (size_t i = 0; i + 1 < bytes.size(); i += 2) {
    uint16_t addr = bytes[i] | (bytes[i + 1] << 8);

    if (LooksLikeAddress(addr, address_map, binary)) {
      valid_length += 2;
    } else {
      // Stop at first non-address pair
      break;
    }
  }

  // Only consider it a table if we have at least 2 valid addresses (4 bytes)
  return (valid_length >= 4) ? valid_length : 0;
}

// Helper: Check if data looks like an address table
static bool LooksLikeAddressTable(const std::vector<uint8_t>& bytes,
                                   const core::AddressMap* address_map = nullptr,
                                   const core::Binary* binary = nullptr) {
  size_t table_length = FindAddressTableLength(bytes, address_map, binary);
  // Consider it a table if at least half the data forms valid addresses
  // and we have at least 4 bytes (2 addresses)
  if (table_length < 4 || table_length < bytes.size() / 2) {
    return false;
  }

  // Additional heuristic: If all bytes have high bits set AND form printable ASCII,
  // it's likely a high-ASCII string, not an address table
  bool all_high_bit = true;
  bool all_printable = true;
  for (size_t i = 0; i < table_length && i < bytes.size(); ++i) {
    if ((bytes[i] & 0x80) == 0) {
      all_high_bit = false;
    }
    if (!IsPrintable(bytes[i])) {
      all_printable = false;
    }
  }

  // If all bytes are high-ASCII printable, treat as string not address table
  if (all_high_bit && all_printable) {
    return false;
  }

  return true;
}

std::string MerlinFormatter::FormatDataRegion(
    uint32_t address,
    const std::vector<uint8_t>& bytes,
    const core::AddressMap* address_map,
    const core::SymbolTable* symbol_table,
    const core::Binary* binary) {

  std::ostringstream out;

  // Add label if this address has one
  if (address_map && address_map->HasLabel(address)) {
    std::string label = address_map->GetLabel(address);
    out << label << std::string(OPCODE_COL - label.length(), ' ');
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
  bool is_address_table = !is_inline_data && LooksLikeAddressTable(bytes, address_map, binary);

  // Check for string: either all bytes are printable, OR there's an embedded string
  bool is_pure_string = !is_inline_data && !is_address_table && bytes.size() >= 3;
  bool has_high_bit = false;
  for (size_t i = 0; i < bytes.size() && is_pure_string; ++i) {
    if (!IsPrintable(bytes[i]) && bytes[i] != 0x8D) {  // Allow CR ($8D)
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
    out << FormatDataRegion(address + embedded_string_pos, string_bytes, address_map, symbol_table, binary);
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
    // Find the actual length of consecutive valid addresses
    size_t table_length = FindAddressTableLength(bytes, address_map, binary);

    if (table_length > 0 && table_length <= bytes.size()) {
      // Format the address table portion
      out << "DA    ";
      for (size_t i = 0; i < table_length; i += 2) {
        if (i > 0) out << ",";
        if (i > 0 && i % 16 == 0) {
          // Max 8 addresses per line
          out << std::endl << std::string(OPCODE_COL, ' ') << "DA    ";
        }
        uint16_t addr = bytes[i] | (bytes[i + 1] << 8);

        // Try to substitute with symbol name
        bool found_symbol = false;

        // Priority 1: Try symbol table first
        if (symbol_table && symbol_table->HasSymbol(addr)) {
          out << symbol_table->GetSymbolName(addr);
          found_symbol = true;
        }

        // Priority 2: Check address map for labels
        if (!found_symbol && address_map && address_map->HasLabel(addr)) {
          out << address_map->GetLabel(addr);
          found_symbol = true;
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
          if (i > table_length && (i - table_length) % 8 == 0) {
            out << std::endl << std::string(OPCODE_COL, ' ') << "HEX   ";
          }
          out << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
              << static_cast<int>(bytes[i]);
        }
      }
    } else {
      // Shouldn't happen, but fall back to HEX if table_length is invalid
      out << "HEX   ";
      for (size_t i = 0; i < bytes.size(); ++i) {
        if (i > 0 && i % 8 == 0) {
          out << std::endl << std::string(OPCODE_COL, ' ') << "HEX   ";
        }
        out << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
            << static_cast<int>(bytes[i]);
      }
    }
  } else {
    // Format as hex bytes (8 per line max)
    out << "HEX   ";
    for (size_t i = 0; i < bytes.size(); ++i) {
      if (i > 0 && i % 8 == 0) {
        out << std::endl << std::string(OPCODE_COL, ' ') << "HEX   ";
      }
      out << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
          << static_cast<int>(bytes[i]);
    }
  }

  // Add comment showing address range
  out << std::string(5, ' ') << "; $" << FormatAddress(address, 4);
  if (bytes.size() > 1) {
    out << "-$" << FormatAddress(address + bytes.size() - 1, 4);
  }

  return out.str();
}

std::string MerlinFormatter::FormatHeader(const core::Binary& binary) {
  std::ostringstream out;

  out << "*" << std::string(39, '-') << std::endl;
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
  return std::string(OPCODE_COL, ' ') + "CHK";
}

std::string MerlinFormatter::FormatAddress(uint32_t address, int width) const {
  std::ostringstream out;
  out << std::hex << std::uppercase << std::setw(width) 
      << std::setfill('0') << address;
  return out.str();
}

std::string MerlinFormatter::GetLabel(uint32_t address,
                                      const core::AddressMap* address_map) const {
  if (address_map && address_map->HasLabel(address)) {
    return address_map->GetLabel(address);
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
