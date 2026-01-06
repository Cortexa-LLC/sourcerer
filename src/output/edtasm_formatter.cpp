// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "output/edtasm_formatter.h"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <set>

#include "analysis/equate_generator.h"
#include "output/data_collector.h"
#include "output/address_analyzer.h"
#include "output/label_resolver.h"
#include "utils/logger.h"

namespace sourcerer {
namespace output {

std::string EdtasmFormatter::Format(
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

  // Collect all referenced addresses from instructions
  auto referenced_addresses = address_analyzer.CollectReferencedAddresses(instructions);

  // Output EQU statements for platform symbols that are referenced
  if (symbol_table) {
    std::set<std::string> output_symbols;  // Track to avoid duplicates
    for (uint32_t ref_addr : referenced_addresses) {
      if (auto symbol_name = symbol_table->GetSymbolName(ref_addr)) {
        // C++ Core Guidelines: Use structured binding with optional
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
            out << "; " << comment;
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

  // NEW: Iterate through entire address space, outputting both CODE and DATA
  uint32_t address = binary.load_address();
  uint32_t end_address = address + binary.size();
  size_t inst_index = 0;

  while (address < end_address) {
    // Check if this address is CODE or DATA
    bool is_code = address_map && address_map->IsCode(address);
    bool is_data = address_map && (address_map->IsData(address) ||
                                   address_map->GetType(address) == core::AddressType::UNKNOWN);

    if (is_code) {
      // Find corresponding instruction
      if (inst_index < instructions.size() &&
          instructions[inst_index].address == address) {
        const auto& inst = instructions[inst_index];

        // Add separator for subroutines
        if (address_map) {
          if (auto label = address_map->GetLabel(inst.address)) {
            if (IsSubroutineLabel(*label)) {
              out << "* " << std::string(38, '-') << std::endl;
            }
          }
        }

        out << FormatInstruction(inst, address_map, symbol_table, equate_gen) << std::endl;
        address += inst.bytes.size();
        inst_index++;
      } else {
        // CODE region but no instruction at this address
        // This can happen for orphaned CODE bytes or misalignments
        // Output as FCB to ensure complete coverage
        uint32_t orphan_start = address;
        address++;  // Move past first byte

        // Collect up to 8 bytes without instructions
        while (address < end_address &&
               (inst_index >= instructions.size() || instructions[inst_index].address != address) &&
               address - orphan_start < 8) {
          address++;
        }

        size_t orphan_size = address - orphan_start;
        const uint8_t* data = binary.GetPointer(orphan_start);
        if (data && orphan_size > 0) {
          // Don't output labels for orphaned CODE bytes (avoid duplicate EQU/label)
          out << FormatBinaryData(orphan_start, data, orphan_size, nullptr);
        }
      }
    } else if (is_data) {
      // Find extent of contiguous DATA region
      // Stop at next labeled address so it gets its own line
      uint32_t data_start = address;
      address++;  // Move past first byte
      while (address < end_address && address_map &&
             (address_map->IsData(address) ||
              address_map->GetType(address) == core::AddressType::UNKNOWN)) {
        // Stop if next address has a label (it needs its own DATA block)
        if (address_map->HasLabel(address)) {
          break;
        }
        address++;
      }
      size_t data_size = address - data_start;

      // Get data bytes
      const uint8_t* data = binary.GetPointer(data_start);
      if (data && data_size > 0) {
        // Check for jump table metadata from analyzer
        bool is_jump_table = false;
        if (address_map) {
          if (auto comment = address_map->GetComment(data_start)) {
            if (comment->find("JUMPTABLE:") == 0) {
              is_jump_table = true;
            }
          }
        }

        // Format based on data type
        if (is_jump_table) {
          // Jump tables are always FDB (16-bit addresses)
          out << FormatWordData(data_start, data, data_size, address_map);
        } else if (IsStringData(data, data_size)) {
          out << FormatStringData(data_start, data, data_size, address_map);
        } else {
          out << FormatBinaryData(data_start, data, data_size, address_map);
        }
      }
    } else {
      // UNKNOWN or unclassified - output as FCB to ensure complete coverage
      uint32_t unknown_start = address;
      address++;

      // Collect up to 8 contiguous UNKNOWN bytes
      while (address < end_address &&
             (!address_map || (!address_map->IsCode(address) && !address_map->IsData(address))) &&
             address - unknown_start < 8) {
        address++;
      }

      size_t unknown_size = address - unknown_start;
      const uint8_t* data = binary.GetPointer(unknown_start);
      if (data && unknown_size > 0) {
        out << FormatBinaryData(unknown_start, data, unknown_size, address_map);
      }
    }
  }

  // Footer
  out << std::endl << FormatFooter();

  return out.str();
}

std::string EdtasmFormatter::FormatInstruction(
    const core::Instruction& inst,
    const core::AddressMap* address_map,
    const core::SymbolTable* symbol_table,
    const analysis::EquateGenerator* equate_gen) {

  (void)equate_gen;  // May be used for equate substitution

  std::ostringstream out;

  // Label column
  std::string label = GetLabel(inst.address, address_map);
  if (!label.empty()) {
    out << label;
  }

  // Pad to opcode column
  int current_col = label.length();
  if (current_col < OPCODE_COL) {
    out << std::string(OPCODE_COL - current_col, ' ');
  } else if (current_col > 0) {
    // Label too long, put opcode on next line
    out << std::endl << std::string(OPCODE_COL, ' ');
  }

  // Opcode (mnemonic) - adjust for branch distance if needed
  std::string mnemonic = inst.mnemonic;

  // For branch instructions, check if we need to use long form
  // This handles cases where addresses shift during reassembly
  if (inst.is_branch && inst.target_address != 0 && !inst.is_call) {
    // Calculate distance (target - PC after this instruction)
    int32_t distance = static_cast<int32_t>(inst.target_address) -
                       static_cast<int32_t>(inst.address + inst.bytes.size());

    // If distance exceeds short branch range (-128 to +127), use long branch
    // Use threshold of +/-60 for safety margin to account for address shifts
    // during reassembly (invalid instructions removed, data/code reclassified)
    // This conservative threshold handles cases where DATA removal shortens distances
    if (distance > 60 || distance < -60) {
      // Convert short branch to long branch mnemonic
      if (mnemonic == "BRA") mnemonic = "LBRA";
      else if (mnemonic == "BRN") mnemonic = "LBRN";
      else if (mnemonic == "BHI") mnemonic = "LBHI";
      else if (mnemonic == "BLS") mnemonic = "LBLS";
      else if (mnemonic == "BCC" || mnemonic == "BHS") mnemonic = "LBHS";
      else if (mnemonic == "BCS" || mnemonic == "BLO") mnemonic = "LBLO";
      else if (mnemonic == "BNE") mnemonic = "LBNE";
      else if (mnemonic == "BEQ") mnemonic = "LBEQ";
      else if (mnemonic == "BVC") mnemonic = "LBVC";
      else if (mnemonic == "BVS") mnemonic = "LBVS";
      else if (mnemonic == "BPL") mnemonic = "LBPL";
      else if (mnemonic == "BMI") mnemonic = "LBMI";
      else if (mnemonic == "BGE") mnemonic = "LBGE";
      else if (mnemonic == "BLT") mnemonic = "LBLT";
      else if (mnemonic == "BGT") mnemonic = "LBGT";
      else if (mnemonic == "BLE") mnemonic = "LBLE";
      else if (mnemonic == "BSR") mnemonic = "LBSR";
    }
  }

  out << std::left << std::setw(6) << mnemonic;

  // Operand with symbol substitution
  if (!inst.operand.empty()) {
    std::string operand = inst.operand;

    // Try to substitute labels and symbols for target addresses
    if (inst.target_address != 0) {
      // First check address_map for generated labels
      if (address_map) {
        if (auto label = address_map->GetLabel(inst.target_address)) {
          operand = *label;
        }
      }
      // Fall back to symbol table for platform symbols
      else if (symbol_table) {
        if (auto symbol_name = symbol_table->GetSymbolName(inst.target_address)) {
          operand = *symbol_name;
        }
      }
    }

    out << operand;
  }

  // Comment column
  int line_length = OPCODE_COL + 6;
  if (!inst.operand.empty()) {
    line_length += inst.operand.length();
  }

  if (line_length < COMMENT_COL) {
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

    // Priority 3: Branch instruction comments with flag indicators
    if (comment.empty() && inst.is_branch) {
      comment = GenerateBranchComment(inst.mnemonic);
    }

    // Priority 4: Semantic comments (platform hints, stack ops, etc.)
    if (comment.empty()) {
      comment = GenerateSemanticComment(inst, symbol_table);
    }

    // Only output comment if we have something meaningful to say
    if (!comment.empty()) {
      out << std::string(COMMENT_COL - line_length, ' ');
      out << "; " << comment;
    }
  }

  return out.str();
}

std::string EdtasmFormatter::FormatData(uint32_t address,
                                       const std::vector<uint8_t>& bytes) {
  (void)address;
  std::ostringstream out;

  // EDTASM+ uses FCB (Form Constant Byte) for byte data
  out << std::string(OPCODE_COL, ' ') << "FCB   ";

  for (size_t i = 0; i < bytes.size(); ++i) {
    if (i > 0) out << ",";
    out << "$" << std::hex << std::uppercase
        << std::setw(2) << std::setfill('0')
        << static_cast<int>(bytes[i]);
  }

  return out.str();
}

std::string EdtasmFormatter::FormatHeader(const core::Binary& binary) {
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

  out << "* " << std::string(38, '-') << std::endl;
  out << "* Sourcerer - Multi-CPU Disassembler" << std::endl;
  out << "* Copyright (C) 2025 Cortexa LLC" << std::endl;
  out << "* Generated: " << time_buf << std::endl;
  out << "* Source: " << binary.source_file() << std::endl;
  out << "* Load Address: $" << FormatAddress(binary.load_address(), 4) << std::endl;
  out << "* Size: " << std::dec << binary.size() << " bytes" << std::endl;
  out << "* " << std::string(38, '-') << std::endl;
  out << std::endl;

  return out.str();
}

std::string EdtasmFormatter::FormatFooter() {
  std::ostringstream out;
  // EDTASM+ uses END directive
  out << std::string(OPCODE_COL, ' ') << "END" << std::endl;
  return out.str();
}

std::string EdtasmFormatter::FormatAddress(uint32_t address, int width) const {
  std::ostringstream out;
  out << std::hex << std::uppercase
      << std::setw(width) << std::setfill('0')
      << address;
  return out.str();
}

std::string EdtasmFormatter::GetLabel(uint32_t address,
                                     const core::AddressMap* address_map) const {
  if (!address_map) {
    return "";
  }

  if (auto label = address_map->GetLabel(address)) {
    return *label;
  }

  return "";
}

bool EdtasmFormatter::IsSubroutineLabel(const std::string& label) const {
  if (label.empty()) {
    return false;
  }

  // Local labels starting with @ or . are not subroutines
  if (label[0] == '@' || label[0] == '.') {
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

  return true;
}

std::string EdtasmFormatter::GenerateBranchComment(const std::string& mnemonic) const {
  // Generate contextual comments for 6809 branch instructions with flag indicators
  if (mnemonic == "BEQ") return "Branch if zero flag set (equal)";
  if (mnemonic == "BNE") return "Branch if zero flag clear (not equal)";
  if (mnemonic == "BCC" || mnemonic == "BHS") return "Branch if carry clear";
  if (mnemonic == "BCS" || mnemonic == "BLO") return "Branch if carry set";
  if (mnemonic == "BPL") return "Branch if negative flag clear (plus)";
  if (mnemonic == "BMI") return "Branch if negative flag set (minus)";
  if (mnemonic == "BVC") return "Branch if overflow clear";
  if (mnemonic == "BVS") return "Branch if overflow set";
  if (mnemonic == "BGE") return "Branch if greater or equal (signed)";
  if (mnemonic == "BLT") return "Branch if less than (signed)";
  if (mnemonic == "BGT") return "Branch if greater than (signed)";
  if (mnemonic == "BLE") return "Branch if less or equal (signed)";
  if (mnemonic == "BHI") return "Branch if higher (unsigned)";
  if (mnemonic == "BLS") return "Branch if lower or same (unsigned)";
  if (mnemonic == "BRA") return "Branch always";

  // Long branches
  if (mnemonic == "LBEQ") return "Long branch if zero flag set (equal)";
  if (mnemonic == "LBNE") return "Long branch if zero flag clear (not equal)";
  if (mnemonic == "LBCC" || mnemonic == "LBHS") return "Long branch if carry clear";
  if (mnemonic == "LBCS" || mnemonic == "LBLO") return "Long branch if carry set";
  if (mnemonic == "LBPL") return "Long branch if negative flag clear (plus)";
  if (mnemonic == "LBMI") return "Long branch if negative flag set (minus)";
  if (mnemonic == "LBVC") return "Long branch if overflow clear";
  if (mnemonic == "LBVS") return "Long branch if overflow set";
  if (mnemonic == "LBGE") return "Long branch if greater or equal (signed)";
  if (mnemonic == "LBLT") return "Long branch if less than (signed)";
  if (mnemonic == "LBGT") return "Long branch if greater than (signed)";
  if (mnemonic == "LBLE") return "Long branch if less or equal (signed)";
  if (mnemonic == "LBHI") return "Long branch if higher (unsigned)";
  if (mnemonic == "LBLS") return "Long branch if lower or same (unsigned)";
  if (mnemonic == "LBRA") return "Long branch always";

  return "";
}

bool EdtasmFormatter::IsPlatformRegister(const std::string& symbol) const {
  // Detect Color Computer platform-specific registers
  if (symbol.find("PIA") == 0) return true;  // PIA0, PIA1, etc.
  if (symbol.find("SAM") == 0) return true;  // SAMREG, SAM registers
  if (symbol == "RSTFLG") return true;       // Reset flag
  if (symbol == "RSTVEC") return true;       // Reset vector
  if (symbol.find("DEVNUM") != std::string::npos) return true;
  if (symbol.find("DSKCON") != std::string::npos) return true;
  if (symbol.find("CINBUF") != std::string::npos) return true;
  if (symbol.find("DFLVEC") != std::string::npos) return true;
  return false;
}

std::string EdtasmFormatter::GetPlatformHint(const std::string& operand,
                                            const core::SymbolTable* symbol_table) const {
  // Extract symbol name from operand (handle $XX, #$XX, symbol+offset, etc.)
  std::string symbol;

  // Find the base symbol name
  size_t plus_pos = operand.find('+');
  size_t comma_pos = operand.find(',');

  if (plus_pos != std::string::npos) {
    symbol = operand.substr(0, plus_pos);
  } else if (comma_pos != std::string::npos) {
    symbol = operand.substr(0, comma_pos);
  } else {
    symbol = operand;
  }

  // Try to extract address from operand (e.g., "$FF20" or "#$FF20")
  if (symbol_table) {
    std::string addr_str = symbol;
    // Strip leading # if present (immediate mode)
    if (!addr_str.empty() && addr_str[0] == '#') {
      addr_str = addr_str.substr(1);
    }
    // Check if it starts with $
    if (!addr_str.empty() && addr_str[0] == '$') {
      try {
        uint32_t address = std::stoul(addr_str.substr(1), nullptr, 16);
        // Look up address in symbol table
        if (auto sym = symbol_table->GetSymbol(address)) {
          if (!sym->description.empty()) {
            return sym->description;
          }
          // Fall back to symbol name if no description
          if (!sym->name.empty()) {
            return sym->name;
          }
        }
      } catch (...) {
        // Invalid address format, continue to named symbol lookup
      }
    }
  }

  // Check for PIA registers (fallback for named symbols)
  if (symbol == "PIA0") {
    if (operand.find("+1") != std::string::npos) return "PIA0 Control A (keyboard IRQ)";
    if (operand.find("+2") != std::string::npos) return "PIA0 Data B (keyboard cols/cassette)";
    if (operand.find("+3") != std::string::npos) return "PIA0 Control B (sound/cassette motor)";
    return "PIA0 Data A (keyboard rows)";
  }

  if (symbol == "PIA1") {
    if (operand.find("+1") != std::string::npos) return "PIA1 Control A (HSYNC IRQ)";
    if (operand.find("+2") != std::string::npos) return "PIA1 Data B (VDG mode/printer)";
    if (operand.find("+3") != std::string::npos) return "PIA1 Control B (VSYNC IRQ)";
    return "PIA1 Data A (6-bit DAC/RS-232)";
  }

  // Other known symbols
  if (symbol == "RSTFLG") return "Warm start flag";
  if (symbol == "RSTVEC") return "Warm start vector";

  return "";
}

std::string EdtasmFormatter::GenerateSemanticComment(
    const core::Instruction& inst,
    const core::SymbolTable* symbol_table) const {

  // Don't generate comments for instructions with user-provided comments
  if (!inst.comment.empty()) {
    return inst.comment;
  }

  // Platform-specific hints for known registers
  if (symbol_table && !inst.operand.empty()) {
    std::string hint = GetPlatformHint(inst.operand, symbol_table);
    if (!hint.empty()) {
      // Contextualize based on operation
      if (inst.mnemonic == "LDA" || inst.mnemonic == "LDB" ||
          inst.mnemonic == "LDD" || inst.mnemonic == "LDX" ||
          inst.mnemonic == "LDY" || inst.mnemonic == "LDU" ||
          inst.mnemonic == "LDS") {
        return "Load from " + hint;
      }
      if (inst.mnemonic == "STA" || inst.mnemonic == "STB" ||
          inst.mnemonic == "STD" || inst.mnemonic == "STX" ||
          inst.mnemonic == "STY" || inst.mnemonic == "STU" ||
          inst.mnemonic == "STS") {
        return "Store to " + hint;
      }
      if (inst.mnemonic == "CLR" || inst.mnemonic == "CLRA" || inst.mnemonic == "CLRB") {
        return "Clear " + hint;
      }
      if (inst.mnemonic == "TST" || inst.mnemonic == "TSTA" || inst.mnemonic == "TSTB") {
        return "Test " + hint;
      }
      // Default: just return the hint
      return hint;
    }
  }

  // Subroutine calls - don't add generic comment
  if (inst.is_call || inst.is_return) {
    return "";
  }

  // Jumps - no generic comment
  if (inst.is_jump) {
    return "";
  }

  // Stack operations
  if (inst.mnemonic == "PSHS") return "Push to hardware stack";
  if (inst.mnemonic == "PULS") return "Pull from hardware stack";
  if (inst.mnemonic == "PSHU") return "Push to user stack";
  if (inst.mnemonic == "PULU") return "Pull from user stack";

  // Register transfers
  if (inst.mnemonic == "TFR") return "Transfer registers";
  if (inst.mnemonic == "EXG") return "Exchange registers";

  // Interrupts
  if (inst.mnemonic == "SWI") return "Software interrupt";
  if (inst.mnemonic == "SWI2") return "Software interrupt 2";
  if (inst.mnemonic == "SWI3") return "Software interrupt 3";
  if (inst.mnemonic == "CWAI") return "Clear CC and wait for interrupt";
  if (inst.mnemonic == "SYNC") return "Sync to interrupt";
  if (inst.mnemonic == "RTI") return "Return from interrupt";

  // Default: no comment (better than useless address comment)
  return "";
}

// NEW: Data output helper methods

bool EdtasmFormatter::IsStringData(const uint8_t* data, size_t size) const {
  // Very short regions are unlikely to be intentional strings
  // They're more likely random data that happens to be printable
  if (size < 8) return false;

  // CRITICAL: Reject sequences with high-bit bytes (>= 0x80)
  // These are graphics data or non-ASCII bytes, not strings
  for (size_t i = 0; i < size; ++i) {
    if (data[i] >= 0x80) {
      return false;  // Not ASCII text
    }
  }

  // If size is even and all pairs look like valid addresses, prefer FDB over FCC
  // This handles jump tables that happen to have printable ASCII bytes
  if (size >= 4 && size % 2 == 0) {
    int valid_addresses = 0;
    int total_words = size / 2;

    for (size_t i = 0; i < size; i += 2) {
      uint16_t word = (static_cast<uint16_t>(data[i]) << 8) | data[i + 1];
      // Valid 6809 address ranges (excluding zero page for data)
      // Common ROM: $8000-$FEFF, RAM: $0100-$7FFF
      if (word >= 0x0100) {
        valid_addresses++;
      }
    }

    // If >75% look like valid addresses, treat as FDB not FCC
    float addr_ratio = static_cast<float>(valid_addresses) / static_cast<float>(total_words);
    if (addr_ratio > 0.75f) {
      return false;  // Use FDB, not FCC
    }
  }

  // Count printable characters
  // Also reject sequences with control characters (except CR/LF)
  int printable = 0;
  for (size_t i = 0; i < size; ++i) {
    uint8_t byte = data[i] & 0x7F;  // Ignore high bit
    if ((byte >= 0x20 && byte < 0x7F) || byte == 0x0D || byte == 0x0A) {
      printable++;
    } else if (byte < 0x20 && byte != 0x0D && byte != 0x0A) {
      // Control character (not CR/LF) - reject as string
      return false;
    }
  }

  // Must be >80% printable to be considered a string
  float ratio = static_cast<float>(printable) / static_cast<float>(size);
  return ratio > 0.8f;
}

std::string EdtasmFormatter::FormatStringData(uint32_t address,
                                             const uint8_t* data,
                                             size_t size,
                                             const core::AddressMap* address_map) const {
  std::ostringstream out;

  // Break into lines (max ~40 chars per line for readability)
  size_t offset = 0;
  while (offset < size) {
    // Label if exists
    std::string label = GetLabel(address + offset, address_map);
    if (!label.empty()) {
      out << label;
      int pad = std::max(1, OPCODE_COL - static_cast<int>(label.length()));
      out << std::string(pad, ' ');
    } else {
      out << std::string(OPCODE_COL, ' ');
    }

    // First pass: scan to find which bytes will actually be in the string
    bool has_char[256] = {false};
    for (size_t scan = offset; scan < size && (scan - offset) < 40; ++scan) {
      uint8_t b = data[scan] & 0x7F;
      if (b == 0x0D || b < 0x20 || b >= 0x7F) break;
      has_char[b] = true;
    }

    // Choose delimiter that doesn't appear in the string
    // Try in order: " / | ~ ` ! @ # $ % ^ & *
    char delimiter = '"';
    const char delimiters[] = "\"/|~`!@#$%^&*";
    for (int i = 0; delimiters[i] != '\0'; ++i) {
      if (!has_char[static_cast<uint8_t>(delimiters[i])]) {
        delimiter = delimiters[i];
        break;
      }
    }

    // FCC directive with chosen delimiter
    out << "FCC   " << delimiter;

    // Output characters (using same logic as scan)
    size_t line_len = 0;
    size_t line_start_offset = offset;
    while (offset < size && line_len < 40) {
      uint8_t byte = data[offset] & 0x7F;  // Strip high bit
      if (byte == 0x0D) {  // CR
        break;  // End this FCC line
      } else if (byte >= 0x20 && byte < 0x7F) {
        // Double-check delimiter (shouldn't happen if scan worked)
        if (byte == delimiter) {
          // If we encounter our delimiter, we chose wrong - output as hex instead
          out << delimiter << std::endl;
          out << std::string(OPCODE_COL, ' ') << "FCB   $" << std::hex
              << std::uppercase << std::setw(2) << std::setfill('0')
              << static_cast<int>(byte);
          offset++;
          goto skip_delimiter;
        }
        out << static_cast<char>(byte);
        line_len++;
        offset++;
      } else {
        break;  // Non-printable, end string
      }
    }

    out << delimiter;
skip_delimiter:
    out << std::endl;

    // Handle CR or other terminators - ALWAYS advance past non-printable
    if (offset < size && (data[offset] == 0x0D || data[offset] < 0x20 || (data[offset] & 0x7F) >= 0x7F)) {
      offset++;  // Skip terminator/non-printable
    }

    // Safety: if we didn't advance at all, force advance to prevent infinite loop
    if (offset == line_start_offset) {
      offset++;
    }
  }

  return out.str();
}

std::string EdtasmFormatter::FormatBinaryData(uint32_t address,
                                             const uint8_t* data,
                                             size_t size,
                                             const core::AddressMap* address_map) const {
  std::ostringstream out;

  // Output 8 bytes per line
  const size_t BYTES_PER_LINE = 8;
  size_t offset = 0;

  while (offset < size) {
    // Label if exists
    std::string label = GetLabel(address + offset, address_map);
    if (!label.empty()) {
      out << label;
      int pad = std::max(1, OPCODE_COL - static_cast<int>(label.length()));
      out << std::string(pad, ' ');
    } else {
      out << std::string(OPCODE_COL, ' ');
    }

    // FCB directive
    out << "FCB   ";

    // Output bytes
    size_t line_bytes = std::min(BYTES_PER_LINE, size - offset);
    for (size_t i = 0; i < line_bytes; ++i) {
      if (i > 0) out << ",";
      out << "$" << std::hex << std::uppercase << std::setw(2)
          << std::setfill('0') << static_cast<int>(data[offset + i]);
    }
    out << std::endl;

    offset += line_bytes;
  }

  return out.str();
}

std::string EdtasmFormatter::FormatWordData(uint32_t address,
                                           const uint8_t* data,
                                           size_t size,
                                           const core::AddressMap* address_map) const {
  std::ostringstream out;

  // Output 4 words per line (8 bytes)
  const size_t WORDS_PER_LINE = 4;
  size_t offset = 0;

  while (offset < size) {
    // Label if exists
    std::string label = GetLabel(address + offset, address_map);
    if (!label.empty()) {
      out << label;
      int pad = std::max(1, OPCODE_COL - static_cast<int>(label.length()));
      out << std::string(pad, ' ');
    } else {
      out << std::string(OPCODE_COL, ' ');
    }

    // FDB directive (Form Double Byte - 16-bit words)
    out << "FDB   ";

    // Output words (big-endian for 6809)
    size_t line_words = std::min(WORDS_PER_LINE, (size - offset) / 2);
    for (size_t i = 0; i < line_words; ++i) {
      if (i > 0) out << ",";
      uint16_t word = (static_cast<uint16_t>(data[offset + i * 2]) << 8) |
                      data[offset + i * 2 + 1];
      out << "$" << std::hex << std::uppercase << std::setw(4)
          << std::setfill('0') << word;
    }
    out << std::endl;

    offset += line_words * 2;

    // Handle odd byte at end
    if (offset == size - 1) {
      out << std::string(OPCODE_COL, ' ') << "FCB   $" << std::hex
          << std::uppercase << std::setw(2) << std::setfill('0')
          << static_cast<int>(data[offset]) << std::endl;
      offset++;
    }
  }

  return out.str();
}

std::unique_ptr<Formatter> CreateEdtasmFormatter() {
  return std::make_unique<EdtasmFormatter>();
}

}  // namespace output
}  // namespace sourcerer
