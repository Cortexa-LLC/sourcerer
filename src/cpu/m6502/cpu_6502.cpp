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
                                       uint32_t address) {
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
                                   uint32_t* target_address) {
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

std::unique_ptr<CpuPlugin> Create6502Plugin() {
  return std::make_unique<Cpu6502>(CpuVariant::MOS_6502);
}

std::unique_ptr<CpuPlugin> Create65C02Plugin() {
  return std::make_unique<Cpu6502>(CpuVariant::WDC_65C02);
}

}  // namespace m6502
}  // namespace cpu
}  // namespace sourcerer
