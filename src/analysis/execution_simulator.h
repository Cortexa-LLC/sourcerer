// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_ANALYSIS_EXECUTION_SIMULATOR_H_
#define SOURCERER_ANALYSIS_EXECUTION_SIMULATOR_H_

#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <vector>

#include "core/binary.h"
#include "core/instruction.h"
#include "cpu/cpu_plugin.h"
#include "cpu/cpu_state.h"

namespace sourcerer {
namespace analysis {

// Execution simulator for dynamic analysis
class ExecutionSimulator {
 public:
  ExecutionSimulator(cpu::CpuPlugin* cpu, const core::Binary* binary);

  // Simulate execution from an address
  // Returns set of discovered code addresses (branch targets that were taken)
  std::set<uint32_t> SimulateFrom(uint32_t start_address, int max_instructions = 1000);

  // Check if a branch at given address would be taken with current state
  bool WouldBranchBeTaken(uint32_t branch_address);

 private:
  cpu::CpuPlugin* cpu_;
  const core::Binary* binary_;
  std::unique_ptr<cpu::CpuState> state_;

  // Track which addresses we've executed
  std::set<uint32_t> executed_addresses_;

  // Discovered code addresses (branch/call targets)
  std::set<uint32_t> discovered_addresses_;

  // Memory snapshot (for reads/writes during simulation)
  std::map<uint32_t, uint8_t> memory_;

  // Execute a single instruction, return false if can't continue
  bool ExecuteInstruction(const core::Instruction& inst);

  // Read byte from simulated memory (binary or modified memory)
  uint8_t ReadByte(uint32_t address);
  uint16_t ReadWord(uint32_t address);

  // Write byte to simulated memory
  void WriteByte(uint32_t address, uint8_t value);
};

}  // namespace analysis
}  // namespace sourcerer

#endif  // SOURCERER_ANALYSIS_EXECUTION_SIMULATOR_H_
