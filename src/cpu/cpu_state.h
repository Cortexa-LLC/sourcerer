// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_CPU_CPU_STATE_H_
#define SOURCERER_CPU_CPU_STATE_H_

#include <cstdint>
#include <functional>
#include <string>

namespace sourcerer {

// Forward declarations
namespace core {
struct Instruction;
}

namespace cpu {

// Abstract CPU state for execution simulation
// Each CPU plugin provides its own concrete implementation
class CpuState {
 public:
  virtual ~CpuState() noexcept = default;

  // Reset CPU state to initial values
  virtual void Reset() noexcept = 0;

  // Program counter access
  virtual uint32_t GetPC() const noexcept = 0;
  virtual void SetPC(uint32_t pc) noexcept = 0;

  // Evaluate branch condition based on current state
  // Returns true if branch would be taken, false otherwise
  virtual bool EvaluateBranchCondition(const std::string& mnemonic) = 0;

  // Memory access callbacks for simulation
  using ReadMemoryCallback = std::function<uint8_t(uint32_t)>;
  using WriteMemoryCallback = std::function<void(uint32_t, uint8_t)>;

  // Execute a single instruction, updating CPU state (registers, flags)
  // Returns false if simulation should stop (illegal instruction, etc.)
  // Note: Control flow (branches, jumps, calls) should still be handled
  // by ExecutionSimulator, this only handles data operations
  virtual bool ExecuteInstruction(const core::Instruction& inst,
                                   ReadMemoryCallback read,
                                   WriteMemoryCallback write) = 0;
};

}  // namespace cpu
}  // namespace sourcerer

#endif  // SOURCERER_CPU_CPU_STATE_H_
