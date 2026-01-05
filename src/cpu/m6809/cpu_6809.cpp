// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "cpu/m6809/cpu_6809.h"

#include <iomanip>
#include <sstream>
#include <vector>

#include "cpu/m6809/indexed_mode.h"
#include "cpu/m6809/opcodes_6809.h"

namespace sourcerer {
namespace cpu {
namespace m6809 {

Cpu6809::Cpu6809() {}

core::Instruction Cpu6809::Disassemble(const uint8_t* data, size_t size,
                                       uint32_t address) const {
  core::Instruction inst;
  inst.address = address;

  if (size == 0) {
    inst.mnemonic = "???";
    inst.is_illegal = true;
    return inst;
  }

  // Get opcode info (handles page prefixes)
  size_t opcode_bytes = 0;
  const OpcodeInfo6809& info = GetOpcodeInfo(data, size, &opcode_bytes);

  // Copy instruction bytes (start with opcode)
  for (size_t i = 0; i < opcode_bytes && i < size; ++i) {
    inst.bytes.push_back(data[i]);
  }

  // Set instruction properties
  inst.mnemonic = info.mnemonic ? info.mnemonic : "???";
  inst.mode = info.mode;
  inst.is_branch = info.is_branch;
  inst.is_jump = info.is_jump;
  inst.is_call = info.is_call;
  inst.is_return = info.is_return;
  inst.is_illegal = info.is_illegal;

  // Format operand and get additional bytes
  size_t extra_bytes = 0;
  bool operand_valid = true;
  IndexedModeResult indexed_result;  // Capture indexed mode details
  bool is_indexed_mode = (info.mode == core::AddressingMode::INDEXED);

  if (is_indexed_mode && size - opcode_bytes > 0) {
    // Parse indexed mode to check for indirect addressing
    indexed_result = ParseIndexedMode(data + opcode_bytes, size - opcode_bytes,
                                     address, opcode_bytes);
    inst.operand = indexed_result.operand;
    extra_bytes = 1 + indexed_result.size;  // post-byte + additional bytes
    if (indexed_result.target_address != 0) {
      inst.target_address = indexed_result.target_address;
    }
    operand_valid = indexed_result.is_valid;
  } else {
    inst.operand = FormatOperand(info.mode, data + opcode_bytes,
                                size - opcode_bytes, address, &inst.target_address,
                                &extra_bytes, &operand_valid, opcode_bytes);
  }

  // Copy additional operand bytes
  for (size_t i = 0; i < extra_bytes && (opcode_bytes + i) < size; ++i) {
    inst.bytes.push_back(data[opcode_bytes + i]);
  }

  // Validate: if operand couldn't be decoded, mark instruction as illegal
  // This ensures incomplete decoding results in DATA, not CODE
  if (!operand_valid) {
    inst.is_illegal = true;
  }

  // CRITICAL: Validate operand combinations for specific instructions
  // Some 6809 instructions don't support indirect indexed addressing
  if (is_indexed_mode && indexed_result.is_indirect && !inst.mnemonic.empty()) {
    // Instructions that DON'T support indirect indexed addressing:
    // TST, JMP, JSR, LEA*/PSHS/PULS/etc (some are impossible, some are invalid)
    if (inst.mnemonic == "TST" || inst.mnemonic == "JMP" || inst.mnemonic == "JSR" ||
        inst.mnemonic == "LEAX" || inst.mnemonic == "LEAY" || inst.mnemonic == "LEAS" ||
        inst.mnemonic == "LEAU") {
      // Indirect addressing not valid for these instructions
      inst.is_illegal = true;
    }
  }

  return inst;
}

size_t Cpu6809::GetInstructionSize(const uint8_t* data, size_t size,
                                   uint32_t address) {
  if (size == 0) return 1;

  size_t opcode_bytes = 0;
  const OpcodeInfo6809& info = GetOpcodeInfo(data, size, &opcode_bytes);

  size_t total_size = opcode_bytes;

  // Calculate size based on addressing mode
  switch (info.mode) {
    case core::AddressingMode::IMPLIED:
      break;  // No additional bytes

    case core::AddressingMode::IMMEDIATE:
      // Size depends on instruction (8-bit or 16-bit immediate)
      if (info.size > opcode_bytes) {
        total_size += (info.size - opcode_bytes);
      }
      break;

    case core::AddressingMode::DIRECT:
      total_size += 1;  // 8-bit address
      break;

    case core::AddressingMode::EXTENDED:
      total_size += 2;  // 16-bit address
      break;

    case core::AddressingMode::RELATIVE:
      // 8-bit or 16-bit offset depending on instruction
      if (info.size > opcode_bytes) {
        total_size += (info.size - opcode_bytes);
      }
      break;

    case core::AddressingMode::INDEXED:
      // Variable size depending on post-byte
      if (opcode_bytes < size) {
        IndexedModeResult indexed = ParseIndexedMode(data + opcode_bytes,
                                                     size - opcode_bytes, address,
                                                     opcode_bytes);
        total_size += 1 + indexed.size;  // post-byte + extra bytes
      }
      break;

    default:
      break;
  }

  return total_size;
}

std::string Cpu6809::FormatOperand(core::AddressingMode mode,
                                  const uint8_t* data, size_t size,
                                  uint32_t address, uint32_t* target_address,
                                  size_t* extra_bytes, bool* success,
                                  size_t opcode_length) const {
  *target_address = 0;
  *extra_bytes = 0;
  *success = true;  // Assume success unless we fail to decode

  std::ostringstream oss;

  switch (mode) {
    case core::AddressingMode::IMPLIED:
      return "";

    case core::AddressingMode::IMMEDIATE:
      if (size >= 1) {
        // Check for TFR/EXG register pair encoding
        if (data[-1] == 0x1F || data[-1] == 0x1E) {
          // TFR (0x1F) or EXG (0x1E) - decode register pair
          bool pair_valid = true;
          oss << DecodeRegisterPair(data[0], &pair_valid);
          *extra_bytes = 1;

          // Propagate validation failure
          if (!pair_valid) {
            *success = false;
          }
        }
        // Check for PSHS/PSHU/PULS/PULU register list encoding
        else if (data[-1] == 0x34 || data[-1] == 0x35 ||
                 data[-1] == 0x36 || data[-1] == 0x37) {
          // PSHS/PULS/PSHU/PULU - decode register list from postbyte
          uint8_t postbyte = data[0];
          bool is_s_stack = (data[-1] == 0x34 || data[-1] == 0x35);  // PSHS/PULS

          std::vector<std::string> regs;
          if (postbyte & 0x01) regs.push_back("CC");
          if (postbyte & 0x02) regs.push_back("A");
          if (postbyte & 0x04) regs.push_back("B");
          if (postbyte & 0x08) regs.push_back("DP");
          if (postbyte & 0x10) regs.push_back("X");
          if (postbyte & 0x20) regs.push_back("Y");
          if (postbyte & 0x40) regs.push_back(is_s_stack ? "U" : "S");
          if (postbyte & 0x80) regs.push_back("PC");

          if (regs.empty()) {
            // No registers specified - invalid but show the byte
            oss << "#$" << std::hex << std::uppercase << std::setw(2)
                << std::setfill('0') << static_cast<int>(postbyte);
          } else {
            // Join register names with commas
            for (size_t i = 0; i < regs.size(); ++i) {
              if (i > 0) oss << ",";
              oss << regs[i];
            }
          }
          *extra_bytes = 1;
        }
        // Normal immediate value
        else {
          // Check if 16-bit immediate (D register loads/compares, index register loads)
          // data[-1] is the opcode byte
          if (size >= 2 && (data[-1] == 0x83 || data[-1] == 0x8C || data[-1] == 0x8E ||
                           data[-1] == 0xC3 || data[-1] == 0xCC || data[-1] == 0xCE)) {
            // 16-bit immediate
            uint16_t val = Read16(data, 0);
            oss << "#$" << std::hex << std::uppercase << std::setw(4)
                << std::setfill('0') << val;
            *extra_bytes = 2;
          } else {
            // 8-bit immediate
            oss << "#$" << std::hex << std::uppercase << std::setw(2)
                << std::setfill('0') << static_cast<int>(data[0]);
            *extra_bytes = 1;

            // Validate: if there's a second byte that looks like it should be immediate data,
            // but the opcode only takes 8-bit, mark as invalid
            if (size >= 2) {
              uint8_t next_byte = data[1];
              // If next byte looks like continuation of immediate (non-zero, not an opcode)
              // and current instruction is 8-bit immediate only, this is likely invalid
              if (next_byte != 0x00 && (next_byte < 0x80 || next_byte > 0xFE)) {
                // Check if this creates an invalid 16-bit immediate for 8-bit instruction
                uint16_t would_be_16bit = (static_cast<uint16_t>(data[0]) << 8) | next_byte;
                if (would_be_16bit > 0xFF && data[0] != 0x00) {
                  // This looks like 16-bit immediate but opcode only accepts 8-bit
                  *success = false;
                }
              }
            }
          }
        }
      } else {
        *success = false;
        oss << "#$??";
      }
      break;

    case core::AddressingMode::DIRECT:
      if (size >= 1) {
        oss << "$" << std::hex << std::uppercase << std::setw(2)
            << std::setfill('0') << static_cast<int>(data[0]);
        *extra_bytes = 1;
      } else {
        *success = false;
        oss << "$??";
      }
      break;

    case core::AddressingMode::EXTENDED:
      if (size >= 2) {
        uint16_t addr = Read16(data, 0);
        *target_address = addr;  // Set target for xref tracking (e.g., LEAX, JMP)
        oss << "$" << std::hex << std::uppercase << std::setw(4)
            << std::setfill('0') << addr;
        *extra_bytes = 2;
      } else {
        *success = false;
        oss << "$????";
      }
      break;

    case core::AddressingMode::RELATIVE: {
      // Determine if this is a long branch (2-byte opcode) or short (1-byte)
      // For long branches, opcode_length will be 2 (page prefix + opcode)
      // For short branches, opcode_length will be 1
      bool is_long_branch = (opcode_length == 2);

      if (!is_long_branch && size >= 1) {
        // 8-bit relative (short branch)
        int8_t offset = static_cast<int8_t>(data[0]);
        // PC-relative from: instruction address + opcode length + offset bytes
        *target_address = (address + opcode_length + 1 + offset) & 0xFFFF;

        oss << "$" << std::hex << std::uppercase << std::setw(4)
            << std::setfill('0') << *target_address;
        *extra_bytes = 1;
      } else if (is_long_branch && size >= 2) {
        // 16-bit relative (long branch)
        int16_t offset = static_cast<int16_t>(Read16(data, 0));
        // PC-relative from: instruction address + opcode length + offset bytes
        *target_address = (address + opcode_length + 2 + offset) & 0xFFFF;
        oss << "$" << std::hex << std::uppercase << std::setw(4)
            << std::setfill('0') << *target_address;
        *extra_bytes = 2;
      } else {
        *success = false;
        oss << "$????";
      }
      break;
    }

    case core::AddressingMode::INDEXED: {
      IndexedModeResult indexed = ParseIndexedMode(data, size, address,
                                                   opcode_length);
      oss << indexed.operand;
      *extra_bytes = 1 + indexed.size;  // post-byte + additional bytes
      if (indexed.target_address != 0) {
        *target_address = indexed.target_address;
      }
      // Propagate validation failure (invalid combinations like [,S+])
      if (!indexed.is_valid) {
        *success = false;
      }
      break;
    }

    default:
      *success = false;
      oss << "???";
      break;
  }

  return oss.str();
}

uint16_t Cpu6809::Read16(const uint8_t* data, size_t offset) const {
  // 6809 uses big-endian byte order
  return (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
}

std::string Cpu6809::DecodeRegisterPair(uint8_t post_byte, bool* valid) const {
  // Assume valid unless proven otherwise
  *valid = true;

  // TFR/EXG post-byte: high nibble = source, low nibble = dest
  uint8_t src = (post_byte >> 4) & 0x0F;
  uint8_t dst = post_byte & 0x0F;

  // Validate register codes and return register name
  auto get_reg_info = [](uint8_t reg) -> std::pair<const char*, bool> {
    switch (reg) {
      // 16-bit registers
      case 0x0: return {"D", true};   // 16-bit accumulator
      case 0x1: return {"X", true};   // Index register X
      case 0x2: return {"Y", true};   // Index register Y
      case 0x3: return {"U", true};   // User stack pointer
      case 0x4: return {"S", true};   // Hardware stack pointer
      case 0x5: return {"PC", true};  // Program counter
      // 8-bit registers
      case 0x8: return {"A", true};   // Accumulator A (8-bit)
      case 0x9: return {"B", true};   // Accumulator B (8-bit)
      case 0xA: return {"CC", true};  // Condition codes
      case 0xB: return {"DP", true};  // Direct page register
      // Invalid codes: 0x6, 0x7, 0xC-0xF
      default:  return {"?", false};  // Invalid register
    }
  };

  auto [src_name, src_valid] = get_reg_info(src);
  auto [dst_name, dst_valid] = get_reg_info(dst);

  // Check if both registers are valid
  if (!src_valid || !dst_valid) {
    *valid = false;
    std::ostringstream oss;
    oss << src_name << "," << dst_name;
    return oss.str();
  }

  // Check size compatibility (16-bit vs 8-bit)
  // 16-bit: 0-5, 8-bit: 8-B
  bool src_is_16bit = (src <= 0x5);
  bool dst_is_16bit = (dst <= 0x5);

  if (src_is_16bit != dst_is_16bit) {
    // Size mismatch - invalid for TFR/EXG
    *valid = false;
  }

  std::ostringstream oss;
  oss << src_name << "," << dst_name;
  return oss.str();
}

// CPU-specific analysis methods (SOLID architecture)
AnalysisCapabilities Cpu6809::GetAnalysisCapabilities() const {
  AnalysisCapabilities caps;
  caps.has_interrupt_vectors = true;
  caps.has_subroutines = true;
  caps.code_alignment = 1;  // Byte-aligned
  return caps;
}

std::vector<InterruptVector> Cpu6809::GetInterruptVectors() const {
  // 6809 has 7 interrupt vectors at top of memory
  return {
    {0xFFF2, "SWI3"},
    {0xFFF4, "SWI2"},
    {0xFFF6, "FIRQ"},
    {0xFFF8, "IRQ"},
    {0xFFFA, "SWI"},
    {0xFFFC, "NMI"},
    {0xFFFE, "RESET"}
  };
}

uint32_t Cpu6809::ReadVectorTarget(const uint8_t* data, size_t size,
                                   uint32_t vector_address) const {
  // Need 2 bytes for vector (big-endian 16-bit address)
  if (size < 2) return 0;
  if (vector_address > size - 2) return 0;

  // 6809 is big-endian
  uint16_t target = (static_cast<uint16_t>(data[vector_address]) << 8) |
                    data[vector_address + 1];
  return target;
}

bool Cpu6809::LooksLikeSubroutineStart(const uint8_t* data, size_t size,
                                       uint32_t address) const {
  if (size < 8) return false;  // Need at least a few bytes

  try {
    int inst_count = 0;
    const int MAX_SCAN = 8;
    size_t offset = 0;

    // Look for common 6809 subroutine patterns
    while (inst_count < MAX_SCAN && offset < size && offset < 32) {
      core::Instruction inst = Disassemble(data + offset, size - offset, address + offset);

      // Illegal opcodes suggest data
      if (inst.is_illegal || inst.bytes.empty()) return false;

      // PSHS at start is strong indicator of subroutine entry
      if (inst_count == 0 && inst.mnemonic == "PSHS") return true;

      // Common register operations at function start
      if (inst.mnemonic == "PSHS" || inst.mnemonic == "PULS" ||
          inst.mnemonic == "LDA" || inst.mnemonic == "LDB" ||
          inst.mnemonic == "LDD" || inst.mnemonic == "STD" ||
          inst.mnemonic == "LEAX" || inst.mnemonic == "LEAY") {
        // Valid instruction, continue
      }

      // Early return suggests not a typical subroutine
      if (inst_count < 3 && inst.is_return) return false;

      // Too many branches early suggests jump table/data
      if (inst.is_branch && inst_count < 2) return false;

      offset += inst.bytes.size();
      inst_count++;
    }

    // Successfully scanned several valid instructions
    return inst_count >= 4;

  } catch (...) {
    return false;
  }
}

bool Cpu6809::IsLikelyCode(const uint8_t* data, size_t size, uint32_t address,
                          size_t scan_length) const {
  if (size == 0) return false;

  try {
    int valid_instructions = 0;
    int illegal_count = 0;
    size_t bytes_scanned = 0;

    while (bytes_scanned < scan_length && bytes_scanned < size) {
      core::Instruction inst = Disassemble(data + bytes_scanned,
                                          size - bytes_scanned,
                                          address + bytes_scanned);

      if (inst.is_illegal || inst.bytes.empty()) {
        illegal_count++;
        if (illegal_count > 2) return false;  // Too many illegal opcodes
        bytes_scanned++;  // Skip this byte
      } else {
        valid_instructions++;
        bytes_scanned += inst.bytes.size();
      }
    }

    return valid_instructions >= 3 && illegal_count == 0;

  } catch (...) {
    return false;
  }
}

std::unique_ptr<CpuPlugin> Create6809Plugin() {
  return std::make_unique<Cpu6809>();
}

}  // namespace m6809
}  // namespace cpu
}  // namespace sourcerer
