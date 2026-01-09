// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "analysis/execution_simulator.h"

#include <iostream>
#include <sstream>
#include <iomanip>

#include "utils/logger.h"

namespace sourcerer {
namespace analysis {

ExecutionSimulator::ExecutionSimulator(cpu::CpuPlugin* cpu, const core::Binary* binary)
    : cpu_(cpu), binary_(binary), state_(cpu->CreateCpuState()) {
  state_->Reset();
}

std::set<uint32_t> ExecutionSimulator::SimulateFrom(uint32_t start_address,
                                                    int max_instructions) {
  state_->Reset();
  state_->SetPC(start_address);
  executed_addresses_.clear();
  discovered_addresses_.clear();

  std::stringstream ss;
  ss << std::hex << std::uppercase << "$" << start_address;
  LOG_INFO("Starting execution simulation from " + ss.str());

  int instruction_count = 0;

  while (instruction_count < max_instructions) {
    uint32_t current_pc = state_->GetPC();

    // Check if we've already executed this address (loop detection)
    if (executed_addresses_.count(current_pc)) {
      break;
    }

    // Check if address is valid
    if (!binary_->IsValidAddress(current_pc)) {
      break;
    }

    executed_addresses_.insert(current_pc);

    // Disassemble instruction
    const uint8_t* data = binary_->GetPointer(current_pc);
    size_t remaining = binary_->load_address() + binary_->size() - current_pc;
    if (!data || remaining == 0) {
      break;
    }

    core::Instruction inst;
    try {
      inst = cpu_->Disassemble(data, remaining, current_pc);
    } catch (const std::out_of_range&) {
      // Address out of bounds - stop simulation
      break;
    } catch (const std::runtime_error&) {
      // Invalid opcode or disassembly error - stop simulation
      break;
    }

    if (inst.bytes.empty() || inst.is_illegal) {
      break;
    }

    // Advance PC
    state_->SetPC(current_pc + inst.bytes.size());

    // Execute instruction
    bool can_continue = ExecuteInstruction(inst);
    if (!can_continue) {
      // Can't continue (RTS, undefined, etc.)
      break;
    }

    instruction_count++;
  }

  ss.str("");
  ss << "Simulation completed: " << instruction_count << " instructions, "
     << discovered_addresses_.size() << " addresses discovered";
  LOG_INFO(ss.str());

  return discovered_addresses_;
}

bool ExecutionSimulator::WouldBranchBeTaken(uint32_t branch_address) {
  // Disassemble the branch instruction
  const uint8_t* data = binary_->GetPointer(branch_address);
  if (!data) return false;

  size_t remaining = binary_->load_address() + binary_->size() - branch_address;
  core::Instruction inst;
  try {
    inst = cpu_->Disassemble(data, remaining, branch_address);
  } catch (const std::out_of_range&) {
    // Address out of bounds
    return false;
  } catch (const std::runtime_error&) {
    // Invalid opcode or disassembly error
    return false;
  }

  if (!inst.is_branch) return false;

  return state_->EvaluateBranchCondition(inst.mnemonic);
}

bool ExecutionSimulator::ExecuteInstruction(const core::Instruction& inst) {
  const std::string& mnem = inst.mnemonic;

  // Returns (stop simulation)
  if (inst.is_return) {
    LOG_DEBUG("RTS/RTI encountered, stopping simulation");
    return false;
  }

  // Branches
  if (inst.is_branch) {
    bool taken = state_->EvaluateBranchCondition(mnem);
    if (taken && inst.target_address != 0) {
      std::stringstream ss;
      ss << std::hex << std::uppercase << "$" << inst.target_address;
      LOG_DEBUG("Branch " + mnem + " taken to " + ss.str());

      discovered_addresses_.insert(inst.target_address);
      state_->SetPC(inst.target_address);
    } else {
      LOG_DEBUG("Branch " + mnem + " not taken");
      // PC already advanced, just continue
    }
    return true;
  }

  // Jumps and Calls
  if (inst.is_jump || inst.is_call) {
    if (inst.target_address != 0) {
      discovered_addresses_.insert(inst.target_address);

      // For JSR, we'd need to track the stack, but for discovery we just note the target
      // Don't follow JSR for now to avoid deep recursion
      if (inst.is_call) {
        LOG_DEBUG("JSR to target (not following)");
        return true;  // Continue after JSR
      }

      // JMP - follow it
      state_->SetPC(inst.target_address);
      return true;
    }
    // Indirect jump with no known target - stop
    return false;
  }

  // Delegate instruction execution to CPU-specific state
  auto read_callback = [this](uint32_t addr) { return ReadByte(addr); };
  auto write_callback = [this](uint32_t addr, uint8_t val) { WriteByte(addr, val); };

  return state_->ExecuteInstruction(inst, read_callback, write_callback);
}

uint8_t ExecutionSimulator::ReadByte(uint32_t address) {
  // Check if we've written to this address
  auto it = memory_.find(address);
  if (it != memory_.end()) {
    return it->second;
  }

  // Otherwise read from binary
  if (binary_->IsValidAddress(address)) {
    return binary_->GetByte(address);
  }

  return 0;  // Default for invalid addresses
}

uint16_t ExecutionSimulator::ReadWord(uint32_t address) {
  uint8_t hi = ReadByte(address);
  uint8_t lo = ReadByte(address + 1);
  return (static_cast<uint16_t>(hi) << 8) | lo;
}

void ExecutionSimulator::WriteByte(uint32_t address, uint8_t value) {
  memory_[address] = value;
}

}  // namespace analysis
}  // namespace sourcerer
