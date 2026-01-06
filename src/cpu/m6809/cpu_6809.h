// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_CPU_M6809_CPU_6809_H_
#define SOURCERER_CPU_M6809_CPU_6809_H_

#include <memory>
#include <string>
#include <vector>

#include "cpu/cpu_plugin.h"
#include "core/instruction.h"

namespace sourcerer {
namespace cpu {
namespace m6809 {

// 6809 CPU plugin
class Cpu6809 : public CpuPlugin {
 public:
  Cpu6809();
  ~Cpu6809() override = default;

  // CpuPlugin interface
  std::string Name() const override { return "6809"; }
  std::vector<std::string> Aliases() const override {
    return {"6809", "motorola6809", "m6809"};
  }
  CpuVariant GetVariant() const override { return CpuVariant::MOTOROLA_6809; }

  core::Instruction Disassemble(const uint8_t* data, size_t size,
                                uint32_t address) const override;

  size_t GetInstructionSize(const uint8_t* data, size_t size,
                            uint32_t address) override;

  uint32_t MaxAddress() const override { return 0xFFFF; }
  uint32_t AddressMask() const override { return 0xFFFF; }

  // CPU-specific analysis methods (SOLID architecture)
  AnalysisCapabilities GetAnalysisCapabilities() const override;
  std::vector<InterruptVector> GetInterruptVectors() const override;
  uint32_t ReadVectorTarget(const uint8_t* data, size_t size,
                            uint32_t vector_address) const override;
  bool LooksLikeSubroutineStart(const uint8_t* data, size_t size,
                                uint32_t address) const override;
  bool IsLikelyCode(const uint8_t* data, size_t size, uint32_t address,
                   size_t scan_length = 16) const override;

 private:
  // Format operand string based on addressing mode
  std::string FormatOperand(core::AddressingMode mode, const uint8_t* data,
                           size_t size, uint32_t address,
                           uint32_t* target_address, size_t* extra_bytes,
                           bool* success, size_t opcode_length) const;

  // Read 16-bit value (big-endian)
  uint16_t Read16(const uint8_t* data, size_t offset) const;

  // Decode TFR/EXG register pair post-byte
  // Sets *valid = false if register codes are invalid
  std::string DecodeRegisterPair(uint8_t post_byte, bool* valid) const;
};

// Factory function
std::unique_ptr<CpuPlugin> Create6809Plugin();

}  // namespace m6809
}  // namespace cpu
}  // namespace sourcerer

#endif  // SOURCERER_CPU_M6809_CPU_6809_H_
