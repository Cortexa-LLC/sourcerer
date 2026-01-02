// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_CPU_M6502_CPU_6502_H_
#define SOURCERER_CPU_M6502_CPU_6502_H_

#include <memory>
#include <string>
#include <vector>

#include "cpu/cpu_plugin.h"

namespace sourcerer {
namespace cpu {
namespace m6502 {

// 6502 family CPU plugin
// Supports: 6502, 65C02, (65816 in Phase 11)
class Cpu6502 : public CpuPlugin {
 public:
  explicit Cpu6502(CpuVariant variant = CpuVariant::MOS_6502);
  ~Cpu6502() override = default;

  // CpuPlugin interface implementation
  std::string Name() const override;
  std::vector<std::string> Aliases() const override;
  CpuVariant GetVariant() const override { return variant_; }

  core::Instruction Disassemble(const uint8_t* data, size_t size,
                                uint32_t address) override;

  size_t GetInstructionSize(const uint8_t* data, size_t size,
                            uint32_t address) override;

  bool Supports16Bit() const override { return false; }  // True for 65816
  uint32_t MaxAddress() const override { return 0xFFFF; }
  uint32_t AddressMask() const override { return 0xFFFF; }

 private:
  CpuVariant variant_;
  bool allow_illegal_;

  // Format operand string based on addressing mode
  std::string FormatOperand(core::AddressingMode mode,
                           const uint8_t* data,
                           size_t size,
                           uint32_t address,
                           uint32_t* target_address);

  // Helper to read 16-bit value (little-endian)
  uint16_t Read16(const uint8_t* data, size_t offset) const;
};

// Factory functions
std::unique_ptr<CpuPlugin> Create6502Plugin();
std::unique_ptr<CpuPlugin> Create65C02Plugin();

}  // namespace m6502
}  // namespace cpu
}  // namespace sourcerer

#endif  // SOURCERER_CPU_M6502_CPU_6502_H_
