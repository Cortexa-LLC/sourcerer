// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_CPU_M6502_CPU_STATE_6502_H_
#define SOURCERER_CPU_M6502_CPU_STATE_6502_H_

#include <cstdint>
#include <string>

#include "cpu/cpu_state.h"

namespace sourcerer {
namespace cpu {

// 6502 CPU state for execution simulation
class CpuState6502 : public CpuState {
 public:
  // 8-bit registers
  uint8_t A = 0;   // Accumulator
  uint8_t X = 0;   // X index register
  uint8_t Y = 0;   // Y index register
  uint8_t SP = 0;  // Stack pointer

  // 16-bit program counter
  uint16_t PC = 0;

  // Status register (P)
  uint8_t P = 0;

  // Status register flags
  bool flag_C() const { return (P & 0x01) != 0; }  // Carry
  bool flag_Z() const { return (P & 0x02) != 0; }  // Zero
  bool flag_I() const { return (P & 0x04) != 0; }  // Interrupt disable
  bool flag_D() const { return (P & 0x08) != 0; }  // Decimal mode
  bool flag_B() const { return (P & 0x10) != 0; }  // Break command
  bool flag_V() const { return (P & 0x40) != 0; }  // Overflow
  bool flag_N() const { return (P & 0x80) != 0; }  // Negative

  void set_flag_C(bool v) { if (v) P |= 0x01; else P &= ~0x01; }
  void set_flag_Z(bool v) { if (v) P |= 0x02; else P &= ~0x02; }
  void set_flag_I(bool v) { if (v) P |= 0x04; else P &= ~0x04; }
  void set_flag_D(bool v) { if (v) P |= 0x08; else P &= ~0x08; }
  void set_flag_V(bool v) { if (v) P |= 0x40; else P &= ~0x40; }
  void set_flag_N(bool v) { if (v) P |= 0x80; else P &= ~0x80; }

  // CpuState interface implementation
  void Reset() override {
    A = X = Y = 0;
    SP = 0xFF;  // Stack starts at $01FF
    PC = 0;
    P = 0x20;   // Bit 5 always set
  }

  uint32_t GetPC() const override { return PC; }
  void SetPC(uint32_t pc) override { PC = static_cast<uint16_t>(pc); }

  bool EvaluateBranchCondition(const std::string& mnemonic) override;

  bool ExecuteInstruction(const core::Instruction& inst,
                          ReadMemoryCallback read,
                          WriteMemoryCallback write) override;

 private:
  // Helper methods for instruction execution
  void UpdateNZ(uint8_t value) {
    set_flag_Z(value == 0);
    set_flag_N((value & 0x80) != 0);
  }
};

}  // namespace cpu
}  // namespace sourcerer

#endif  // SOURCERER_CPU_M6502_CPU_STATE_6502_H_
