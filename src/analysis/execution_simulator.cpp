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
    : cpu_(cpu), binary_(binary) {
  state_.Reset();
}

std::set<uint32_t> ExecutionSimulator::SimulateFrom(uint32_t start_address,
                                                    int max_instructions) {
  state_.Reset();
  state_.PC = start_address;
  executed_addresses_.clear();
  discovered_addresses_.clear();

  std::stringstream ss;
  ss << std::hex << std::uppercase << "$" << start_address;
  LOG_INFO("Starting execution simulation from " + ss.str());

  int instruction_count = 0;

  while (instruction_count < max_instructions) {
    uint32_t current_pc = state_.PC;

    // Check if we've already executed this address (loop detection)
    if (executed_addresses_.count(current_pc)) {
      LOG_DEBUG("Loop detected, stopping simulation");
      break;
    }

    // Check if address is valid
    if (!binary_->IsValidAddress(current_pc)) {
      LOG_DEBUG("Reached invalid address, stopping simulation");
      break;
    }

    executed_addresses_.insert(current_pc);

    // Disassemble instruction
    const uint8_t* data = binary_->GetPointer(current_pc);
    size_t remaining = binary_->load_address() + binary_->size() - current_pc;
    if (!data || remaining == 0) break;

    core::Instruction inst;
    try {
      inst = cpu_->Disassemble(data, remaining, current_pc);
    } catch (...) {
      LOG_DEBUG("Failed to disassemble, stopping simulation");
      break;
    }

    if (inst.bytes.empty() || inst.is_illegal) {
      LOG_DEBUG("Illegal instruction, stopping simulation");
      break;
    }

    // Advance PC
    state_.PC = current_pc + inst.bytes.size();

    // Execute instruction
    if (!ExecuteInstruction(inst)) {
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
  } catch (...) {
    return false;
  }

  if (!inst.is_branch) return false;

  return EvaluateBranchCondition(inst.mnemonic);
}

bool ExecutionSimulator::EvaluateBranchCondition(const std::string& mnemonic) {
  // Evaluate 6809 branch conditions based on current CC flags
  if (mnemonic == "BRA" || mnemonic == "LBRA") return true;  // Always

  if (mnemonic == "BEQ" || mnemonic == "LBEQ") return state_.flag_Z();
  if (mnemonic == "BNE" || mnemonic == "LBNE") return !state_.flag_Z();

  if (mnemonic == "BMI" || mnemonic == "LBMI") return state_.flag_N();
  if (mnemonic == "BPL" || mnemonic == "LBPL") return !state_.flag_N();

  if (mnemonic == "BCS" || mnemonic == "BLO" || mnemonic == "LBCS" || mnemonic == "LBLO")
    return state_.flag_C();
  if (mnemonic == "BCC" || mnemonic == "BHS" || mnemonic == "LBCC" || mnemonic == "LBHS")
    return !state_.flag_C();

  if (mnemonic == "BVS" || mnemonic == "LBVS") return state_.flag_V();
  if (mnemonic == "BVC" || mnemonic == "LBVC") return !state_.flag_V();

  // Signed comparisons
  if (mnemonic == "BGT" || mnemonic == "LBGT")
    return !state_.flag_Z() && (state_.flag_N() == state_.flag_V());
  if (mnemonic == "BGE" || mnemonic == "LBGE")
    return (state_.flag_N() == state_.flag_V());
  if (mnemonic == "BLT" || mnemonic == "LBLT")
    return (state_.flag_N() != state_.flag_V());
  if (mnemonic == "BLE" || mnemonic == "LBLE")
    return state_.flag_Z() || (state_.flag_N() != state_.flag_V());

  // Unsigned comparisons
  if (mnemonic == "BHI" || mnemonic == "LBHI")
    return !state_.flag_C() && !state_.flag_Z();
  if (mnemonic == "BLS" || mnemonic == "LBLS")
    return state_.flag_C() || state_.flag_Z();

  // Unknown branch - assume not taken for safety
  LOG_WARNING("Unknown branch mnemonic: " + mnemonic);
  return false;
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
    bool taken = EvaluateBranchCondition(mnem);
    if (taken && inst.target_address != 0) {
      std::stringstream ss;
      ss << std::hex << std::uppercase << "$" << inst.target_address;
      LOG_DEBUG("Branch " + mnem + " taken to " + ss.str());

      discovered_addresses_.insert(inst.target_address);
      state_.PC = inst.target_address;
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
      state_.PC = inst.target_address;
      return true;
    }
    // Indirect jump with no known target - stop
    return false;
  }

  // Arithmetic operations that affect flags
  if (mnem == "DECA") {
    state_.A--;
    UpdateCC_NZ(state_.A);
    return true;
  }
  if (mnem == "DECB") {
    state_.B--;
    UpdateCC_NZ(state_.B);
    return true;
  }
  if (mnem == "INCA") {
    state_.A++;
    UpdateCC_NZ(state_.A);
    return true;
  }
  if (mnem == "INCB") {
    state_.B++;
    UpdateCC_NZ(state_.B);
    return true;
  }

  // Loads with immediate values (we can extract from operand)
  if (mnem == "LDA" && inst.mode == core::AddressingMode::IMMEDIATE) {
    // Extract immediate value from operand string (format: "#$XX")
    if (inst.operand.size() >= 3 && inst.operand[0] == '#' && inst.operand[1] == '$') {
      std::string hex_str = inst.operand.substr(2);
      state_.A = static_cast<uint8_t>(std::stoul(hex_str, nullptr, 16));
      UpdateCC_NZ(state_.A);
    }
    return true;
  }
  if (mnem == "LDB" && inst.mode == core::AddressingMode::IMMEDIATE) {
    if (inst.operand.size() >= 3 && inst.operand[0] == '#' && inst.operand[1] == '$') {
      std::string hex_str = inst.operand.substr(2);
      state_.B = static_cast<uint8_t>(std::stoul(hex_str, nullptr, 16));
      UpdateCC_NZ(state_.B);
    }
    return true;
  }

  // Clear operations
  if (mnem == "CLRA") {
    state_.A = 0;
    state_.set_flag_Z(true);
    state_.set_flag_N(false);
    return true;
  }
  if (mnem == "CLRB") {
    state_.B = 0;
    state_.set_flag_Z(true);
    state_.set_flag_N(false);
    return true;
  }

  // Test operations
  if (mnem == "TSTA") {
    UpdateCC_NZ(state_.A);
    return true;
  }
  if (mnem == "TSTB") {
    UpdateCC_NZ(state_.B);
    return true;
  }

  // For most other instructions, we can't accurately simulate without full state
  // Just continue and assume they don't drastically change control flow
  return true;
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

void ExecutionSimulator::UpdateCC_NZ(uint8_t result) {
  state_.set_flag_Z(result == 0);
  state_.set_flag_N((result & 0x80) != 0);
}

void ExecutionSimulator::UpdateCC_NZ16(uint16_t result) {
  state_.set_flag_Z(result == 0);
  state_.set_flag_N((result & 0x8000) != 0);
}

}  // namespace analysis
}  // namespace sourcerer
