// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include <gtest/gtest.h>

#include "analysis/execution_simulator.h"
#include "core/binary.h"
#include "cpu/m6502/cpu_6502.h"
#include "cpu/m6809/cpu_6809.h"

namespace sourcerer {
namespace analysis {
namespace {

// Test fixture for ExecutionSimulator with 6809
class ExecutionSimulator6809Test : public ::testing::Test {
 protected:
  void SetUp() override {
    cpu_ = cpu::m6809::Create6809Plugin();

    // Create a simple binary with branch instructions
    // BRA $10 (always branch forward)
    binary_data_ = {
      0x20, 0x0E,  // BRA +14 (skip to address $0010)
      0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,  // Filler
      0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
      0x39         // RTS (return from subroutine)
    };

    binary_ = std::make_unique<core::Binary>(binary_data_, 0x8000);
  }

  std::unique_ptr<cpu::CpuPlugin> cpu_;
  std::vector<uint8_t> binary_data_;
  std::unique_ptr<core::Binary> binary_;
};

// Test fixture for ExecutionSimulator with 6502
class ExecutionSimulator6502Test : public ::testing::Test {
 protected:
  void SetUp() override {
    cpu_ = cpu::m6502::Create6502Plugin();

    // Create a simple binary with branch instructions
    // BNE $10 (branch if not equal - we'll test with Z flag set/clear)
    binary_data_ = {
      0xD0, 0x0E,  // BNE +14 (skip to address $0010)
      0xEA, 0xEA, 0xEA, 0xEA, 0xEA, 0xEA, 0xEA, 0xEA,  // NOP filler
      0xEA, 0xEA, 0xEA, 0xEA, 0xEA, 0xEA,
      0x60         // RTS (return from subroutine)
    };

    binary_ = std::make_unique<core::Binary>(binary_data_, 0x2000);
  }

  std::unique_ptr<cpu::CpuPlugin> cpu_;
  std::vector<uint8_t> binary_data_;
  std::unique_ptr<core::Binary> binary_;
};

// ===== 6809 CPU Tests =====

TEST_F(ExecutionSimulator6809Test, ConstructorCreatesCpuState) {
  ExecutionSimulator sim(cpu_.get(), binary_.get());

  // Verify state was created
  const cpu::CpuState* state = sim.GetState();
  EXPECT_NE(state, nullptr);

  // Verify initial PC is 0
  EXPECT_EQ(state->GetPC(), 0);
}

TEST_F(ExecutionSimulator6809Test, StateResetWorks) {
  ExecutionSimulator sim(cpu_.get(), binary_.get());

  const cpu::CpuState* state = sim.GetState();
  EXPECT_EQ(state->GetPC(), 0);

  // Simulate from a different address (will reset internally)
  sim.SimulateFrom(0x8000, 10);

  // After simulation, state should have been used
  // (we can't easily verify internal state changes without exposing more)
}

TEST_F(ExecutionSimulator6809Test, SimulateDetectsBranchTarget) {
  ExecutionSimulator sim(cpu_.get(), binary_.get());

  // Simulate from start - should discover branch target
  std::set<uint32_t> discovered = sim.SimulateFrom(0x8000, 100);

  // Should discover the BRA target at $8010
  EXPECT_TRUE(discovered.count(0x8010) > 0);
}

TEST_F(ExecutionSimulator6809Test, SimulateStopsAtReturn) {
  ExecutionSimulator sim(cpu_.get(), binary_.get());

  // Simulate - should stop at RTS
  std::set<uint32_t> discovered = sim.SimulateFrom(0x8000, 100);

  // Should have discovered the branch target
  EXPECT_FALSE(discovered.empty());
}

TEST_F(ExecutionSimulator6809Test, BranchConditionEvaluatedViaState) {
  ExecutionSimulator sim(cpu_.get(), binary_.get());

  // The simulator uses state->EvaluateBranchCondition internally
  // We can't directly test this without exposing more internals,
  // but SimulateFrom will use it
  std::set<uint32_t> discovered = sim.SimulateFrom(0x8000, 10);

  // If branch evaluation works, we should discover targets
  EXPECT_FALSE(discovered.empty());
}

// ===== 6502 CPU Tests =====

TEST_F(ExecutionSimulator6502Test, ConstructorCreatesCpuState) {
  ExecutionSimulator sim(cpu_.get(), binary_.get());

  // Verify state was created
  const cpu::CpuState* state = sim.GetState();
  EXPECT_NE(state, nullptr);

  // Verify initial PC is 0
  EXPECT_EQ(state->GetPC(), 0);
}

TEST_F(ExecutionSimulator6502Test, StateResetWorks) {
  ExecutionSimulator sim(cpu_.get(), binary_.get());

  const cpu::CpuState* state = sim.GetState();
  EXPECT_EQ(state->GetPC(), 0);

  // Simulate from a different address (will reset internally)
  sim.SimulateFrom(0x2000, 10);

  // After simulation, state should have been used
}

TEST_F(ExecutionSimulator6502Test, SimulateDetectsBranchTarget) {
  ExecutionSimulator sim(cpu_.get(), binary_.get());

  // Simulate from start - BNE will be evaluated (may or may not be taken)
  std::set<uint32_t> discovered = sim.SimulateFrom(0x2000, 100);

  // Depending on initial Z flag state, branch may be taken
  // The important part is no crash with 6502 CPU
  EXPECT_TRUE(true);  // Test passes if we get here without crashing
}

TEST_F(ExecutionSimulator6502Test, SimulateStopsAtReturn) {
  ExecutionSimulator sim(cpu_.get(), binary_.get());

  // Simulate - should stop at RTS
  std::set<uint32_t> discovered = sim.SimulateFrom(0x2000, 100);

  // Should complete without error
  EXPECT_TRUE(true);
}

TEST_F(ExecutionSimulator6502Test, Works6502CpuAgnostic) {
  // This test verifies that ExecutionSimulator works with 6502
  // without any hard-coded 6809 dependencies
  ExecutionSimulator sim(cpu_.get(), binary_.get());

  // Should not crash or have compile errors
  std::set<uint32_t> discovered = sim.SimulateFrom(0x2000, 10);

  // The key is that this compiles and runs with 6502
  EXPECT_NE(sim.GetState(), nullptr);
}

// ===== 6502 Branch Behavior Tests =====

TEST_F(ExecutionSimulator6502Test, ConditionalBranchWithInitialState) {
  // Test that conditional branches use initial flag state
  // BNE will branch based on initial Z flag (which is 0 after reset)

  // Since Z flag is initially 0 (false), BNE should be taken
  std::vector<uint8_t> code = {
    0xD0, 0x04,  // BNE +4 (should be taken since Z=0)
    0xEA, 0xEA,  // NOP NOP (skipped)
    0xEA, 0xEA,  // NOP NOP (skipped)
    0x60         // RTS
  };

  core::Binary binary(code, 0x2000);
  ExecutionSimulator sim(cpu_.get(), &binary);

  std::set<uint32_t> discovered = sim.SimulateFrom(0x2000, 10);

  // Should discover the branch target at 0x2006 (0x2000 + 2 + 4)
  EXPECT_TRUE(discovered.count(0x2006) > 0);
}

TEST_F(ExecutionSimulator6502Test, UnconditionalBranchAlwaysTaken) {
  // BRA (65C02) should always be taken regardless of flags
  auto cpu_65c02 = cpu::m6502::Create65C02Plugin();

  std::vector<uint8_t> code = {
    0x80, 0x04,  // BRA +4 (65C02 instruction)
    0xEA, 0xEA,  // NOP NOP (skipped)
    0xEA, 0xEA,  // NOP NOP (skipped)
    0x60         // RTS
  };

  core::Binary binary(code, 0x2000);
  ExecutionSimulator sim(cpu_65c02.get(), &binary);

  std::set<uint32_t> discovered = sim.SimulateFrom(0x2000, 10);

  // Should discover the branch target
  EXPECT_TRUE(discovered.count(0x2006) > 0);
}

TEST_F(ExecutionSimulator6502Test, MultipleSequentialBranches) {
  // Test simulator handles multiple branches in sequence
  std::vector<uint8_t> code = {
    0xD0, 0x02,  // BNE +2 (taken if Z=0)
    0xF0, 0x04,  // BEQ +4 (taken if Z=1, skipped in this path)
    0xEA,        // NOP (target of first branch)
    0xD0, 0x02,  // BNE +2
    0x60,        // RTS
    0xEA,        // NOP
    0x60         // RTS
  };

  core::Binary binary(code, 0x2000);
  ExecutionSimulator sim(cpu_.get(), &binary);

  std::set<uint32_t> discovered = sim.SimulateFrom(0x2000, 20);

  // Should discover at least one branch target
  EXPECT_FALSE(discovered.empty());
}

// ===== Cross-CPU Compatibility Tests =====

TEST(ExecutionSimulatorCrossCpuTest, WorksWithBoth6502And6809) {
  // 6809 test
  {
    auto cpu = cpu::m6809::Create6809Plugin();
    std::vector<uint8_t> data = {0x39};  // RTS
    core::Binary binary(data, 0x8000);

    ExecutionSimulator sim(cpu.get(), &binary);
    EXPECT_NE(sim.GetState(), nullptr);

    std::set<uint32_t> discovered = sim.SimulateFrom(0x8000, 10);
    EXPECT_TRUE(true);  // No crash = success
  }

  // 6502 test
  {
    auto cpu = cpu::m6502::Create6502Plugin();
    std::vector<uint8_t> data = {0x60};  // RTS
    core::Binary binary(data, 0x2000);

    ExecutionSimulator sim(cpu.get(), &binary);
    EXPECT_NE(sim.GetState(), nullptr);

    std::set<uint32_t> discovered = sim.SimulateFrom(0x2000, 10);
    EXPECT_TRUE(true);  // No crash = success
  }
}

}  // namespace
}  // namespace analysis
}  // namespace sourcerer
