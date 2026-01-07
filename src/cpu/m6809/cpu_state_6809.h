// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_CPU_M6809_CPU_STATE_6809_H_
#define SOURCERER_CPU_M6809_CPU_STATE_6809_H_

#include <cstdint>
#include <string>

#include "cpu/cpu_state.h"

namespace sourcerer {
namespace cpu {

// 6809 CPU state for execution simulation
class CpuState6809 : public CpuState {
 public:
  // 8-bit registers
  uint8_t A = 0;
  uint8_t B = 0;
  uint8_t DP = 0;  // Direct page register

  // 16-bit registers
  uint16_t X = 0;
  uint16_t Y = 0;
  uint16_t U = 0;  // User stack pointer
  uint16_t S = 0;  // Hardware stack pointer
  uint16_t PC = 0; // Program counter

  // Condition codes (8-bit register)
  uint8_t CC = 0;

  // Condition code flags (extracted from CC)
  bool flag_C() const { return (CC & 0x01) != 0; }  // Carry
  bool flag_V() const { return (CC & 0x02) != 0; }  // Overflow
  bool flag_Z() const { return (CC & 0x04) != 0; }  // Zero
  bool flag_N() const { return (CC & 0x08) != 0; }  // Negative
  bool flag_I() const { return (CC & 0x10) != 0; }  // IRQ mask
  bool flag_H() const { return (CC & 0x20) != 0; }  // Half carry
  bool flag_F() const { return (CC & 0x40) != 0; }  // FIRQ mask
  bool flag_E() const { return (CC & 0x80) != 0; }  // Entire flag

  void set_flag_C(bool v) { if (v) CC |= 0x01; else CC &= ~0x01; }
  void set_flag_V(bool v) { if (v) CC |= 0x02; else CC &= ~0x02; }
  void set_flag_Z(bool v) { if (v) CC |= 0x04; else CC &= ~0x04; }
  void set_flag_N(bool v) { if (v) CC |= 0x08; else CC &= ~0x08; }

  // Helper: Get D register (A:B concatenated)
  uint16_t D() const { return (static_cast<uint16_t>(A) << 8) | B; }
  void set_D(uint16_t val) { A = (val >> 8) & 0xFF; B = val & 0xFF; }

  // CpuState interface implementation
  void Reset() override {
    A = B = DP = 0;
    X = Y = U = S = PC = 0;
    CC = 0;
  }

  uint32_t GetPC() const override { return PC; }
  void SetPC(uint32_t pc) override { PC = static_cast<uint16_t>(pc); }

  bool EvaluateBranchCondition(const std::string& mnemonic) override;

  bool ExecuteInstruction(const core::Instruction& inst,
                          ReadMemoryCallback read,
                          WriteMemoryCallback write) override;

 private:
  // Helper methods for instruction execution
  void UpdateNZ8(uint8_t value) {
    set_flag_Z(value == 0);
    set_flag_N((value & 0x80) != 0);
  }

  void UpdateNZ16(uint16_t value) {
    set_flag_Z(value == 0);
    set_flag_N((value & 0x8000) != 0);
  }
};

}  // namespace cpu
}  // namespace sourcerer

#endif  // SOURCERER_CPU_M6809_CPU_STATE_6809_H_
