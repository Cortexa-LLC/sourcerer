// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_ANALYSIS_EXECUTION_SIMULATOR_H_
#define SOURCERER_ANALYSIS_EXECUTION_SIMULATOR_H_

#include <cstdint>
#include <map>
#include <set>
#include <vector>

#include "core/binary.h"
#include "core/instruction.h"
#include "cpu/cpu_plugin.h"

namespace sourcerer {
namespace analysis {

// 6809 CPU state for simulation
struct CpuState6809 {
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

  // Reset state
  void Reset() {
    A = B = DP = 0;
    X = Y = U = S = PC = 0;
    CC = 0;
  }
};

// Execution simulator for dynamic analysis
class ExecutionSimulator {
 public:
  ExecutionSimulator(cpu::CpuPlugin* cpu, const core::Binary* binary);

  // Simulate execution from an address
  // Returns set of discovered code addresses (branch targets that were taken)
  std::set<uint32_t> SimulateFrom(uint32_t start_address, int max_instructions = 1000);

  // Get current CPU state
  const CpuState6809& GetState() const { return state_; }

  // Check if a branch at given address would be taken with current state
  bool WouldBranchBeTaken(uint32_t branch_address);

 private:
  cpu::CpuPlugin* cpu_;
  const core::Binary* binary_;
  CpuState6809 state_;

  // Track which addresses we've executed
  std::set<uint32_t> executed_addresses_;

  // Discovered code addresses (branch/call targets)
  std::set<uint32_t> discovered_addresses_;

  // Memory snapshot (for reads/writes during simulation)
  std::map<uint32_t, uint8_t> memory_;

  // Execute a single instruction, return false if can't continue
  bool ExecuteInstruction(const core::Instruction& inst);

  // Evaluate branch condition based on current CC flags
  bool EvaluateBranchCondition(const std::string& mnemonic);

  // Read byte from simulated memory (binary or modified memory)
  uint8_t ReadByte(uint32_t address);
  uint16_t ReadWord(uint32_t address);

  // Write byte to simulated memory
  void WriteByte(uint32_t address, uint8_t value);

  // Update condition codes based on result
  void UpdateCC_NZ(uint8_t result);
  void UpdateCC_NZ16(uint16_t result);
};

}  // namespace analysis
}  // namespace sourcerer

#endif  // SOURCERER_ANALYSIS_EXECUTION_SIMULATOR_H_
