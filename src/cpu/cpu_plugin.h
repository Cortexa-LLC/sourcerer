// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_CPU_CPU_PLUGIN_H_
#define SOURCERER_CPU_CPU_PLUGIN_H_

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "core/instruction.h"

namespace sourcerer {
namespace cpu {

// CPU variant types
enum class CpuVariant {
  MOS_6502,     // Original NMOS 6502
  WDC_65C02,    // CMOS 65C02 with additional instructions
  WDC_65816,    // 16-bit 65816 (Apple IIgs)
  MOTOROLA_6809,
  ZILOG_Z80,
};

// Abstract CPU plugin interface
class CpuPlugin {
 public:
  virtual ~CpuPlugin() = default;

  // Plugin identification
  virtual std::string Name() const = 0;
  virtual std::vector<std::string> Aliases() const = 0;
  virtual CpuVariant GetVariant() const = 0;

  // Disassemble one instruction at the given address
  // Returns the disassembled instruction
  virtual core::Instruction Disassemble(const uint8_t* data, size_t size,
                                        uint32_t address) = 0;

  // Get instruction size without full disassembly (for quick scanning)
  virtual size_t GetInstructionSize(const uint8_t* data, size_t size,
                                    uint32_t address) = 0;

  // CPU capabilities
  virtual bool Supports16Bit() const { return false; }
  virtual uint32_t MaxAddress() const { return 0xFFFF; }
  virtual uint32_t AddressMask() const { return 0xFFFF; }
};

// Factory function type for creating CPU plugins
using CpuPluginFactory = std::unique_ptr<CpuPlugin> (*)();

}  // namespace cpu
}  // namespace sourcerer

#endif  // SOURCERER_CPU_CPU_PLUGIN_H_
