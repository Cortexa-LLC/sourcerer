// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "cpu/m6502/cpu_6502.h"

#include <iomanip>
#include <sstream>

#include "cpu/m6502/opcodes_6502.h"
#include "utils/logger.h"

namespace sourcerer {
namespace cpu {
namespace m6502 {

Cpu6502::Cpu6502(CpuVariant variant)
    : variant_(variant), allow_illegal_(false) {}

std::string Cpu6502::Name() const {
  switch (variant_) {
    case CpuVariant::MOS_6502:
      return "6502";
    case CpuVariant::WDC_65C02:
      return "65C02";
    case CpuVariant::WDC_65816:
      return "65816";
    default:
      return "Unknown";
  }
}

std::vector<std::string> Cpu6502::Aliases() const {
  switch (variant_) {
    case CpuVariant::MOS_6502:
      return {"6502", "mos6502"};
    case CpuVariant::WDC_65C02:
      return {"65c02", "65C02", "wdc65c02"};
    case CpuVariant::WDC_65816:
      return {"65816", "65C816", "wdc65816"};
    default:
      return {};
  }
}

core::Instruction Cpu6502::Disassemble(const uint8_t* data, size_t size,
                                       uint32_t address) const {
  core::Instruction inst;
  inst.address = address;

  if (size == 0) {
    LOG_ERROR("Disassemble called with zero size");
    return inst;
  }

  uint8_t opcode = data[0];
  const OpcodeInfo& info = GetOpcodeInfo(opcode);

  // Check if valid for this variant
  bool allow_65c02 = (variant_ == CpuVariant::WDC_65C02 ||
                      variant_ == CpuVariant::WDC_65816);
  if (!IsValidOpcode(opcode, allow_65c02, allow_illegal_)) {
    inst.mnemonic = "???";
    inst.operand = "";
    inst.bytes.push_back(opcode);
    inst.mode = core::AddressingMode::UNKNOWN;
    inst.is_illegal = true;
    return inst;
  }

  // Copy instruction bytes
  for (size_t i = 0; i < info.size && i < size; ++i) {
    inst.bytes.push_back(data[i]);
  }

  // Set instruction properties
  inst.mnemonic = info.mnemonic;
  inst.mode = info.mode;
  inst.is_branch = info.is_branch;
  inst.is_jump = info.is_jump;
  inst.is_call = info.is_call;
  inst.is_return = info.is_return;
  inst.is_illegal = info.is_illegal;

  // Format operand
  inst.operand = FormatOperand(info.mode, data, size, address,
                               &inst.target_address);

  return inst;
}

size_t Cpu6502::GetInstructionSize(const uint8_t* data, size_t size,
                                   uint32_t address) {
  (void)address;  // Unused parameter
  if (size == 0) return 0;
  uint8_t opcode = data[0];
  const OpcodeInfo& info = GetOpcodeInfo(opcode);
  return info.size;
}

std::string Cpu6502::FormatOperand(core::AddressingMode mode,
                                   const uint8_t* data,
                                   size_t size,
                                   uint32_t address,
                                   uint32_t* target_address) const {
  std::ostringstream oss;
  *target_address = 0;

  switch (mode) {
    case core::AddressingMode::IMPLIED:
    case core::AddressingMode::ACCUMULATOR:
      return "";

    case core::AddressingMode::IMMEDIATE:
      if (size >= 2) {
        oss << "#$" << std::hex << std::uppercase << std::setfill('0')
            << std::setw(2) << static_cast<int>(data[1]);
      }
      break;

    case core::AddressingMode::ZERO_PAGE:
      if (size >= 2) {
        oss << "$" << std::hex << std::uppercase << std::setfill('0')
            << std::setw(2) << static_cast<int>(data[1]);
      }
      break;

    case core::AddressingMode::ZERO_PAGE_X:
      if (size >= 2) {
        oss << "$" << std::hex << std::uppercase << std::setfill('0')
            << std::setw(2) << static_cast<int>(data[1]) << ",X";
      }
      break;

    case core::AddressingMode::ZERO_PAGE_Y:
      if (size >= 2) {
        oss << "$" << std::hex << std::uppercase << std::setfill('0')
            << std::setw(2) << static_cast<int>(data[1]) << ",Y";
      }
      break;

    case core::AddressingMode::ABSOLUTE:
      if (size >= 3) {
        uint16_t addr = Read16(data, 1);
        *target_address = addr;
        oss << "$" << std::hex << std::uppercase << std::setfill('0')
            << std::setw(4) << addr;
      }
      break;

    case core::AddressingMode::ABSOLUTE_X:
      if (size >= 3) {
        uint16_t addr = Read16(data, 1);
        oss << "$" << std::hex << std::uppercase << std::setfill('0')
            << std::setw(4) << addr << ",X";
      }
      break;

    case core::AddressingMode::ABSOLUTE_Y:
      if (size >= 3) {
        uint16_t addr = Read16(data, 1);
        oss << "$" << std::hex << std::uppercase << std::setfill('0')
            << std::setw(4) << addr << ",Y";
      }
      break;

    case core::AddressingMode::INDIRECT:
      if (size >= 3) {
        uint16_t addr = Read16(data, 1);
        oss << "($" << std::hex << std::uppercase << std::setfill('0')
            << std::setw(4) << addr << ")";
      }
      break;

    case core::AddressingMode::ABSOLUTE_INDEXED_INDIRECT:
      if (size >= 3) {
        uint16_t addr = Read16(data, 1);
        oss << "($" << std::hex << std::uppercase << std::setfill('0')
            << std::setw(4) << addr << ",X)";
      }
      break;

    case core::AddressingMode::INDEXED_INDIRECT:
      if (size >= 2) {
        oss << "($" << std::hex << std::uppercase << std::setfill('0')
            << std::setw(2) << static_cast<int>(data[1]) << ",X)";
      }
      break;

    case core::AddressingMode::INDIRECT_INDEXED:
      if (size >= 2) {
        oss << "($" << std::hex << std::uppercase << std::setfill('0')
            << std::setw(2) << static_cast<int>(data[1]) << "),Y";
      }
      break;

    case core::AddressingMode::RELATIVE:
      if (size >= 2) {
        int8_t offset = static_cast<int8_t>(data[1]);
        uint16_t target = (address + 2 + offset) & 0xFFFF;
        *target_address = target;
        oss << "$" << std::hex << std::uppercase << std::setfill('0')
            << std::setw(4) << target;
      }
      break;

    default:
      oss << "???";
      break;
  }

  return oss.str();
}

uint16_t Cpu6502::Read16(const uint8_t* data, size_t offset) const {
  return data[offset] | (data[offset + 1] << 8);
}

// CPU-specific analysis methods (SOLID architecture)
AnalysisCapabilities Cpu6502::GetAnalysisCapabilities() const {
  AnalysisCapabilities caps;
  caps.has_interrupt_vectors = true;
  caps.has_subroutines = true;
  caps.code_alignment = 1;  // Byte-aligned
  return caps;
}

std::vector<InterruptVector> Cpu6502::GetInterruptVectors() const {
  // 6502 has 3 interrupt vectors at top of memory
  return {
    {0xFFFA, "NMI"},
    {0xFFFC, "RESET"},
    {0xFFFE, "IRQ/BRK"}
  };
}

uint32_t Cpu6502::ReadVectorTarget(const uint8_t* data, size_t size,
                                   uint32_t vector_address) const {
  // Need 2 bytes for vector (little-endian 16-bit address)
  if (size < 2) return 0;
  if (vector_address > size - 2) return 0;

  // 6502 is little-endian
  uint16_t target = data[vector_address] |
                   (static_cast<uint16_t>(data[vector_address + 1]) << 8);
  return target;
}

bool Cpu6502::LooksLikeSubroutineStart(const uint8_t* data, size_t size,
                                       uint32_t address) const {
  if (size < 8) return false;  // Need at least a few bytes

  try {
    int inst_count = 0;
    const int MAX_SCAN = 8;
    size_t offset = 0;

    // Look for common 6502 subroutine patterns
    while (inst_count < MAX_SCAN && offset < size && offset < 32) {
      core::Instruction inst = Disassemble(data + offset, size - offset,
                                          address + offset);

      // Illegal opcodes suggest data
      if (inst.is_illegal || inst.bytes.empty()) return false;

      // PHP or PHA at start is strong indicator of subroutine entry
      if (inst_count == 0 && (inst.mnemonic == "PHP" || inst.mnemonic == "PHA")) {
        return true;
      }

      // Common register operations at function start
      if (inst.mnemonic == "PHP" || inst.mnemonic == "PHA" ||
          inst.mnemonic == "PLA" || inst.mnemonic == "PLP" ||
          inst.mnemonic == "LDA" || inst.mnemonic == "LDX" ||
          inst.mnemonic == "LDY" || inst.mnemonic == "STA" ||
          inst.mnemonic == "STX" || inst.mnemonic == "STY" ||
          inst.mnemonic == "TAX" || inst.mnemonic == "TAY" ||
          inst.mnemonic == "TXA" || inst.mnemonic == "TYA") {
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

bool Cpu6502::IsLikelyCode(const uint8_t* data, size_t size, uint32_t address,
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

std::unique_ptr<CpuPlugin> Create6502Plugin() {
  return std::make_unique<Cpu6502>(CpuVariant::MOS_6502);
}

std::unique_ptr<CpuPlugin> Create65C02Plugin() {
  return std::make_unique<Cpu6502>(CpuVariant::WDC_65C02);
}

}  // namespace m6502
}  // namespace cpu
}  // namespace sourcerer
