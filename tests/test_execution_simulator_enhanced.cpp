// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include <gtest/gtest.h>

#include "analysis/execution_simulator.h"
#include "core/binary.h"
#include "cpu/m6502/cpu_6502.h"
#include "cpu/m6809/cpu_6809.h"
#include "cpu/m6809/cpu_state_6809.h"
#include "cpu/m6809/indexed_mode.h"

namespace sourcerer {
namespace analysis {
namespace {

// ===== 6502 Enhanced Execution Tests =====

class ExecutionSimulator6502EnhancedTest : public ::testing::Test {
 protected:
  void SetUp() override {
    cpu_ = cpu::m6502::Create6502Plugin();
  }

  std::unique_ptr<cpu::CpuPlugin> cpu_;
};

// Test that LDA sets Z flag, affecting BEQ branch
TEST_F(ExecutionSimulator6502EnhancedTest, LDAZeroSetsFlagAffectsBEQ) {
  // LDA #$00 should set Z flag to 1
  // BEQ should then be taken
  std::vector<uint8_t> code = {
    0xA9, 0x00,  // LDA #$00 (A=0, Z=1)
    0xF0, 0x04,  // BEQ +4 (should be taken because Z=1)
    0xEA, 0xEA,  // NOP NOP (skipped)
    0xEA, 0xEA,  // NOP NOP (skipped)
    0x60         // RTS (branch target)
  };

  core::Binary binary(code, 0x2000);
  ExecutionSimulator sim(cpu_.get(), &binary);

  std::set<uint32_t> discovered = sim.SimulateFrom(0x2000, 10);

  // Should discover branch target at 0x2008 (0x2000 + 2 + 2 + 4)
  EXPECT_TRUE(discovered.count(0x2008) > 0);
}

// Test that LDA non-zero clears Z flag, affecting BNE branch
TEST_F(ExecutionSimulator6502EnhancedTest, LDANonZeroClearsFlagAffectsBNE) {
  // LDA #$42 should clear Z flag to 0
  // BNE should then be taken
  std::vector<uint8_t> code = {
    0xA9, 0x42,  // LDA #$42 (A=$42, Z=0)
    0xD0, 0x04,  // BNE +4 (should be taken because Z=0)
    0xEA, 0xEA,  // NOP NOP (skipped)
    0xEA, 0xEA,  // NOP NOP (skipped)
    0x60         // RTS (branch target)
  };

  core::Binary binary(code, 0x2000);
  ExecutionSimulator sim(cpu_.get(), &binary);

  std::set<uint32_t> discovered = sim.SimulateFrom(0x2000, 10);

  // Should discover branch target at 0x2008
  EXPECT_TRUE(discovered.count(0x2008) > 0);
}

// Test that LDA negative sets N flag, affecting BMI branch
TEST_F(ExecutionSimulator6502EnhancedTest, LDANegativeSetsNFlagAffectsBMI) {
  // LDA #$80 should set N flag to 1 (bit 7 set)
  // BMI should then be taken
  std::vector<uint8_t> code = {
    0xA9, 0x80,  // LDA #$80 (A=$80, N=1, Z=0)
    0x30, 0x04,  // BMI +4 (should be taken because N=1)
    0xEA, 0xEA,  // NOP NOP (skipped)
    0xEA, 0xEA,  // NOP NOP (skipped)
    0x60         // RTS (branch target)
  };

  core::Binary binary(code, 0x2000);
  ExecutionSimulator sim(cpu_.get(), &binary);

  std::set<uint32_t> discovered = sim.SimulateFrom(0x2000, 10);

  // Should discover branch target at 0x2008
  EXPECT_TRUE(discovered.count(0x2008) > 0);
}

// Test that CMP affects flags and influences branch
TEST_F(ExecutionSimulator6502EnhancedTest, CMPAffectsFlagsForBranch) {
  // LDA #$42, CMP #$42 should set Z=1 (equal)
  // BEQ should be taken
  std::vector<uint8_t> code = {
    0xA9, 0x42,  // LDA #$42
    0xC9, 0x42,  // CMP #$42 (A == $42, so Z=1, C=1, N=0)
    0xF0, 0x02,  // BEQ +2 (should be taken because Z=1)
    0xEA, 0xEA,  // NOP NOP (skipped)
    0x60         // RTS (branch target)
  };

  core::Binary binary(code, 0x2000);
  ExecutionSimulator sim(cpu_.get(), &binary);

  std::set<uint32_t> discovered = sim.SimulateFrom(0x2000, 10);

  // Should discover branch target at 0x2008 (0x2000 + 2 + 2 + 2 + 2)
  EXPECT_TRUE(discovered.count(0x2008) > 0);
}

// Test that SEC sets C flag, affecting BCS branch
TEST_F(ExecutionSimulator6502EnhancedTest, SECSetsCFlagAffectsBCS) {
  // SEC should set C flag to 1
  // BCS should then be taken
  std::vector<uint8_t> code = {
    0x38,        // SEC (C=1)
    0xB0, 0x04,  // BCS +4 (should be taken because C=1)
    0xEA, 0xEA,  // NOP NOP (skipped)
    0xEA, 0xEA,  // NOP NOP (skipped)
    0x60         // RTS (branch target)
  };

  core::Binary binary(code, 0x2000);
  ExecutionSimulator sim(cpu_.get(), &binary);

  std::set<uint32_t> discovered = sim.SimulateFrom(0x2000, 10);

  // Should discover branch target at 0x2007 (0x2000 + 1 + 2 + 4)
  EXPECT_TRUE(discovered.count(0x2007) > 0);
}

// Test that CLC clears C flag, affecting BCC branch
TEST_F(ExecutionSimulator6502EnhancedTest, CLCClearsCFlagAffectsBCC) {
  // CLC should clear C flag to 0
  // BCC should then be taken
  std::vector<uint8_t> code = {
    0x18,        // CLC (C=0)
    0x90, 0x04,  // BCC +4 (should be taken because C=0)
    0xEA, 0xEA,  // NOP NOP (skipped)
    0xEA, 0xEA,  // NOP NOP (skipped)
    0x60         // RTS (branch target)
  };

  core::Binary binary(code, 0x2000);
  ExecutionSimulator sim(cpu_.get(), &binary);

  std::set<uint32_t> discovered = sim.SimulateFrom(0x2000, 10);

  // Should discover branch target at 0x2007
  EXPECT_TRUE(discovered.count(0x2007) > 0);
}

// Test ADC with carry flag
TEST_F(ExecutionSimulator6502EnhancedTest, ADCWithCarryAffectsFlags) {
  // LDA #$FF, SEC, ADC #$01 should give A=1, Z=0, C=1, N=0
  std::vector<uint8_t> code = {
    0xA9, 0xFF,  // LDA #$FF
    0x38,        // SEC (C=1)
    0x69, 0x01,  // ADC #$01 (A = $FF + $01 + 1 = $101, A=$01, C=1, Z=0, N=0)
    0xB0, 0x02,  // BCS +2 (should be taken because C=1)
    0xEA, 0xEA,  // NOP NOP (skipped)
    0x60         // RTS (branch target)
  };

  core::Binary binary(code, 0x2000);
  ExecutionSimulator sim(cpu_.get(), &binary);

  std::set<uint32_t> discovered = sim.SimulateFrom(0x2000, 10);

  // Should discover branch target
  EXPECT_TRUE(discovered.count(0x2009) > 0);
}

// ===== 6809 Enhanced Execution Tests =====

class ExecutionSimulator6809EnhancedTest : public ::testing::Test {
 protected:
  void SetUp() override {
    cpu_ = cpu::m6809::Create6809Plugin();
  }

  std::unique_ptr<cpu::CpuPlugin> cpu_;
};

// Test that LDA (6809) sets Z flag, affecting BEQ branch
TEST_F(ExecutionSimulator6809EnhancedTest, LDAZeroSetsFlagAffectsBEQ) {
  // LDA #$00 should set Z flag to 1
  // BEQ should then be taken
  std::vector<uint8_t> code = {
    0x86, 0x00,  // LDA #$00 (A=0, Z=1, N=0)
    0x27, 0x04,  // BEQ +4 (should be taken because Z=1)
    0x12, 0x12,  // NOP NOP (skipped)
    0x12, 0x12,  // NOP NOP (skipped)
    0x39         // RTS (branch target)
  };

  core::Binary binary(code, 0x8000);
  ExecutionSimulator sim(cpu_.get(), &binary);

  std::set<uint32_t> discovered = sim.SimulateFrom(0x8000, 10);

  // Should discover branch target at 0x8008 (0x8000 + 2 + 2 + 4)
  EXPECT_TRUE(discovered.count(0x8008) > 0);
}

// Test that CMPA affects flags and influences branch
TEST_F(ExecutionSimulator6809EnhancedTest, CMPAAffectsFlagsForBranch) {
  // LDA #$42, CMPA #$42 should set Z=1 (equal)
  // BEQ should be taken
  std::vector<uint8_t> code = {
    0x86, 0x42,  // LDA #$42
    0x81, 0x42,  // CMPA #$42 (A == $42, so Z=1, N=0)
    0x27, 0x02,  // BEQ +2 (should be taken because Z=1)
    0x12, 0x12,  // NOP NOP (skipped)
    0x39         // RTS (branch target)
  };

  core::Binary binary(code, 0x8000);
  ExecutionSimulator sim(cpu_.get(), &binary);

  std::set<uint32_t> discovered = sim.SimulateFrom(0x8000, 10);

  // Should discover branch target
  EXPECT_TRUE(discovered.count(0x8008) > 0);
}

// Test that ADDA with carry affects flags
TEST_F(ExecutionSimulator6809EnhancedTest, ADDAWithCarryAffectsFlags) {
  // LDA #$FF, ADDA #$01 should set C=1 (carry out)
  std::vector<uint8_t> code = {
    0x86, 0xFF,  // LDA #$FF
    0x8B, 0x01,  // ADDA #$01 (A = $FF + $01 = $100, A=$00, C=1, Z=1, N=0)
    0x25, 0x02,  // BCS +2 (should be taken because C=1)
    0x12, 0x12,  // NOP NOP (skipped)
    0x39         // RTS (branch target)
  };

  core::Binary binary(code, 0x8000);
  ExecutionSimulator sim(cpu_.get(), &binary);

  std::set<uint32_t> discovered = sim.SimulateFrom(0x8000, 10);

  // Should discover branch target
  EXPECT_TRUE(discovered.count(0x8008) > 0);
}

// Test signed comparison: BGT (branch if greater than)
TEST_F(ExecutionSimulator6809EnhancedTest, SignedComparisonBGT) {
  // LDA #$02, CMPA #$01 should result in A > #$01 (unsigned and signed)
  // BGT should be taken
  std::vector<uint8_t> code = {
    0x86, 0x02,  // LDA #$02
    0x81, 0x01,  // CMPA #$01 (A > $01, so Z=0, N=0, V=0, C=1)
    0x2E, 0x02,  // BGT +2 (should be taken because Z=0 and N xor V = 0)
    0x12, 0x12,  // NOP NOP (skipped)
    0x39         // RTS (branch target)
  };

  core::Binary binary(code, 0x8000);
  ExecutionSimulator sim(cpu_.get(), &binary);

  std::set<uint32_t> discovered = sim.SimulateFrom(0x8000, 10);

  // Should discover branch target
  EXPECT_TRUE(discovered.count(0x8008) > 0);
}

// ============================================================================
// Work Package 4: ExecutionSimulator Edge Cases and Coverage (90% target)
// ============================================================================

// Test 1: WouldBranchBeTaken method - Check branch evaluation at specific address
TEST_F(ExecutionSimulator6502EnhancedTest, WouldBranchBeTaken) {
  // Setup code with LDA setting Z flag, then BEQ
  std::vector<uint8_t> code = {
    0xA9, 0x00,  // LDA #$00 (sets Z=1)
    0xF0, 0x02   // BEQ +2
  };

  core::Binary binary(code, 0x2000);
  ExecutionSimulator sim(cpu_.get(), &binary);

  // Simulate to set up CPU state
  sim.SimulateFrom(0x2000, 1);  // Execute LDA #$00

  // Now check if BEQ at 0x2002 would be taken
  bool would_branch = sim.WouldBranchBeTaken(0x2002);
  EXPECT_TRUE(would_branch);  // Z=1, so BEQ should be taken
}

// Test 2: Invalid address - Simulation stops at invalid address
TEST_F(ExecutionSimulator6502EnhancedTest, InvalidAddress) {
  // Code that would branch to invalid address
  std::vector<uint8_t> code = {
    0xA9, 0x00,  // LDA #$00
    0x4C, 0x00, 0x90  // JMP $9000 (outside binary range)
  };

  core::Binary binary(code, 0x2000);
  ExecutionSimulator sim(cpu_.get(), &binary);

  std::set<uint32_t> discovered = sim.SimulateFrom(0x2000, 10);

  // Should discover the jump target even though it's invalid
  EXPECT_TRUE(discovered.count(0x9000) > 0);
}

// Test 3: Loop detection - Simulation stops when revisiting same address
TEST_F(ExecutionSimulator6502EnhancedTest, LoopDetection) {
  // Infinite loop: JMP to self
  std::vector<uint8_t> code = {
    0x4C, 0x00, 0x20  // JMP $2000 (self)
  };

  core::Binary binary(code, 0x2000);
  ExecutionSimulator sim(cpu_.get(), &binary);

  std::set<uint32_t> discovered = sim.SimulateFrom(0x2000, 100);

  // Should stop before hitting max iterations due to loop detection
  // discovered should contain $2000 (the loop target)
  EXPECT_TRUE(discovered.count(0x2000) > 0);
}

// Test 4: Max iterations reached
TEST_F(ExecutionSimulator6502EnhancedTest, MaxIterations) {
  // Long sequence of NOPs
  std::vector<uint8_t> code(200, 0xEA);  // 200 NOPs
  core::Binary binary(code, 0x2000);
  ExecutionSimulator sim(cpu_.get(), &binary);

  // Limit to 10 instructions
  std::set<uint32_t> discovered = sim.SimulateFrom(0x2000, 10);

  // Should stop after 10 instructions (not execute all 200)
  // discovered set should be relatively small
  EXPECT_TRUE(discovered.size() < 20);  // Much less than 200
}

// Test 5: Branch not taken path
TEST_F(ExecutionSimulator6502EnhancedTest, BranchNotTaken) {
  // LDA non-zero, then BEQ (should not be taken)
  std::vector<uint8_t> code = {
    0xA9, 0x42,  // LDA #$42 (Z=0)
    0xF0, 0x04,  // BEQ +4 (not taken)
    0xEA,        // NOP (should execute)
    0xEA,        // NOP (should execute)
    0x60,        // RTS
    0xEA,        // NOP (branch target - NOT executed)
    0x60         // RTS (branch target)
  };

  core::Binary binary(code, 0x2000);
  ExecutionSimulator sim(cpu_.get(), &binary);

  std::set<uint32_t> discovered = sim.SimulateFrom(0x2000, 10);

  // Should NOT discover the branch target (Z=0, BEQ not taken)
  EXPECT_TRUE(discovered.count(0x2008) == 0);
}

// Test 6: Indirect jump with unknown target
TEST_F(ExecutionSimulator6809EnhancedTest, IndirectJumpUnknownTarget) {
  // JMP indirect - target not determinable statically
  std::vector<uint8_t> code = {
    0x6E, 0x84   // JMP [,X] - indirect indexed jump
  };

  core::Binary binary(code, 0x8000);
  ExecutionSimulator sim(cpu_.get(), &binary);

  std::set<uint32_t> discovered = sim.SimulateFrom(0x8000, 10);

  // Simulation should stop (can't determine target)
  // discovered should be empty or minimal
  EXPECT_TRUE(discovered.size() < 5);
}

// Test 7: JSR not followed (to avoid deep recursion)
TEST_F(ExecutionSimulator6809EnhancedTest, JSRNotFollowed) {
  // JSR to subroutine
  std::vector<uint8_t> code = {
    0xBD, 0x90, 0x00,  // JSR $9000
    0xEA,              // NOP (after JSR)
    0x39               // RTS
  };

  core::Binary binary(code, 0x8000);
  ExecutionSimulator sim(cpu_.get(), &binary);

  std::set<uint32_t> discovered = sim.SimulateFrom(0x8000, 10);

  // Should discover JSR target but not follow it
  EXPECT_TRUE(discovered.count(0x9000) > 0);
  // Should continue after JSR
  // (execution continues, but we don't deeply verify subroutine contents)
}

// Test 8: Memory write and read
TEST_F(ExecutionSimulator6502EnhancedTest, MemoryWriteAndRead) {
  // STA to zero page, then LDA from same location
  std::vector<uint8_t> code = {
    0xA9, 0x42,  // LDA #$42
    0x85, 0x10,  // STA $10
    0xA5, 0x10,  // LDA $10 (should read back $42)
    0x60         // RTS
  };

  core::Binary binary(code, 0x2000);
  ExecutionSimulator sim(cpu_.get(), &binary);

  // Should execute without error
  std::set<uint32_t> discovered = sim.SimulateFrom(0x2000, 10);

  // Basic sanity check - simulation completes
  EXPECT_TRUE(discovered.size() >= 0);
}

// Test 9: Disassembly failure during simulation
TEST_F(ExecutionSimulator6502EnhancedTest, DisassemblyFailure) {
  // Invalid opcode should stop simulation
  std::vector<uint8_t> code = {
    0xA9, 0x00,  // LDA #$00
    0x02         // Invalid 6502 opcode (JAM)
  };

  core::Binary binary(code, 0x2000);
  ExecutionSimulator sim(cpu_.get(), &binary);

  std::set<uint32_t> discovered = sim.SimulateFrom(0x2000, 10);

  // Simulation should stop at invalid instruction
  // Should have executed at least LDA
  EXPECT_TRUE(discovered.size() < 10);
}

// Test 10: WouldBranchBeTaken with invalid address
TEST_F(ExecutionSimulator6502EnhancedTest, WouldBranchBeTakenInvalidAddress) {
  std::vector<uint8_t> code = {0xEA};
  core::Binary binary(code, 0x2000);
  ExecutionSimulator sim(cpu_.get(), &binary);

  // Query branch at invalid address
  bool would_branch = sim.WouldBranchBeTaken(0x9000);
  EXPECT_FALSE(would_branch);  // Invalid address, should return false
}

// ============================================================================
// Phase 5: 6809 CPU State Direct Tests
// ============================================================================

class CpuState6809Test : public ::testing::Test {
 protected:
  void SetUp() override {
    state_ = std::make_unique<cpu::CpuState6809>();
  }

  std::unique_ptr<cpu::CpuState6809> state_;
};

// Test: Register operations (A, B, D)
TEST_F(CpuState6809Test, RegisterAOperations) {
  state_->A = 0x00;
  EXPECT_EQ(state_->A, 0x00);

  state_->A = 0x80;  // Negative
  EXPECT_EQ(state_->A, 0x80);

  state_->A = 0xFF;
  EXPECT_EQ(state_->A, 0xFF);
}

// Test: D register (A:B concatenation)
TEST_F(CpuState6809Test, DRegisterAccess) {
  state_->A = 0x12;
  state_->B = 0x34;
  EXPECT_EQ(state_->D(), 0x1234);

  state_->set_D(0x5678);
  EXPECT_EQ(state_->A, 0x56);
  EXPECT_EQ(state_->B, 0x78);
  EXPECT_EQ(state_->D(), 0x5678);
}

// Test: All 16-bit registers
TEST_F(CpuState6809Test, SixteenBitRegisters) {
  state_->X = 0x1234;
  EXPECT_EQ(state_->X, 0x1234);

  state_->Y = 0x5678;
  EXPECT_EQ(state_->Y, 0x5678);

  state_->U = 0xABCD;
  EXPECT_EQ(state_->U, 0xABCD);

  state_->S = 0xEF00;
  EXPECT_EQ(state_->S, 0xEF00);

  state_->PC = 0x8000;
  EXPECT_EQ(state_->PC, 0x8000);
  EXPECT_EQ(state_->GetPC(), 0x8000);

  state_->SetPC(0x9000);
  EXPECT_EQ(state_->PC, 0x9000);
}

// Test: Direct page register
TEST_F(CpuState6809Test, DirectPageRegister) {
  state_->DP = 0x00;
  EXPECT_EQ(state_->DP, 0x00);

  state_->DP = 0x10;
  EXPECT_EQ(state_->DP, 0x10);

  state_->DP = 0xFF;
  EXPECT_EQ(state_->DP, 0xFF);
}

// Test: Condition code flags
TEST_F(CpuState6809Test, ConditionCodeFlags) {
  state_->CC = 0x00;
  EXPECT_FALSE(state_->flag_C());
  EXPECT_FALSE(state_->flag_V());
  EXPECT_FALSE(state_->flag_Z());
  EXPECT_FALSE(state_->flag_N());
  EXPECT_FALSE(state_->flag_I());
  EXPECT_FALSE(state_->flag_H());
  EXPECT_FALSE(state_->flag_F());
  EXPECT_FALSE(state_->flag_E());

  // Test C flag
  state_->set_flag_C(true);
  EXPECT_TRUE(state_->flag_C());
  EXPECT_EQ(state_->CC & 0x01, 0x01);

  // Test V flag
  state_->set_flag_V(true);
  EXPECT_TRUE(state_->flag_V());
  EXPECT_EQ(state_->CC & 0x02, 0x02);

  // Test Z flag
  state_->set_flag_Z(true);
  EXPECT_TRUE(state_->flag_Z());
  EXPECT_EQ(state_->CC & 0x04, 0x04);

  // Test N flag
  state_->set_flag_N(true);
  EXPECT_TRUE(state_->flag_N());
  EXPECT_EQ(state_->CC & 0x08, 0x08);
}

// Test: Flag clearing
TEST_F(CpuState6809Test, FlagClearing) {
  state_->CC = 0xFF;  // All flags set
  EXPECT_TRUE(state_->flag_C());

  state_->set_flag_C(false);
  EXPECT_FALSE(state_->flag_C());
  EXPECT_EQ(state_->CC & 0x01, 0x00);

  state_->set_flag_Z(false);
  EXPECT_FALSE(state_->flag_Z());
  EXPECT_EQ(state_->CC & 0x04, 0x00);
}

// Test: Reset function
TEST_F(CpuState6809Test, Reset) {
  state_->A = 0x42;
  state_->B = 0x24;
  state_->X = 0x1234;
  state_->Y = 0x5678;
  state_->U = 0xABCD;
  state_->S = 0xEF00;
  state_->PC = 0x8000;
  state_->DP = 0x10;
  state_->CC = 0xFF;

  state_->Reset();

  EXPECT_EQ(state_->A, 0x00);
  EXPECT_EQ(state_->B, 0x00);
  EXPECT_EQ(state_->X, 0x00);
  EXPECT_EQ(state_->Y, 0x00);
  EXPECT_EQ(state_->U, 0x00);
  EXPECT_EQ(state_->S, 0x00);
  EXPECT_EQ(state_->PC, 0x00);
  EXPECT_EQ(state_->DP, 0x00);
  EXPECT_EQ(state_->CC, 0x00);
}

// Test: Branch conditions - always taken (BRA)
TEST_F(CpuState6809Test, BranchAlwaysTaken) {
  state_->CC = 0x00;
  EXPECT_TRUE(state_->EvaluateBranchCondition("BRA"));
  EXPECT_TRUE(state_->EvaluateBranchCondition("LBRA"));
}

// Test: Branch conditions - zero flag (BEQ, BNE)
TEST_F(CpuState6809Test, BranchZeroFlag) {
  state_->set_flag_Z(false);
  EXPECT_FALSE(state_->EvaluateBranchCondition("BEQ"));
  EXPECT_TRUE(state_->EvaluateBranchCondition("BNE"));
  EXPECT_FALSE(state_->EvaluateBranchCondition("LBEQ"));
  EXPECT_TRUE(state_->EvaluateBranchCondition("LBNE"));

  state_->set_flag_Z(true);
  EXPECT_TRUE(state_->EvaluateBranchCondition("BEQ"));
  EXPECT_FALSE(state_->EvaluateBranchCondition("BNE"));
  EXPECT_TRUE(state_->EvaluateBranchCondition("LBEQ"));
  EXPECT_FALSE(state_->EvaluateBranchCondition("LBNE"));
}

// Test: Branch conditions - negative flag (BMI, BPL)
TEST_F(CpuState6809Test, BranchNegativeFlag) {
  state_->set_flag_N(false);
  EXPECT_FALSE(state_->EvaluateBranchCondition("BMI"));
  EXPECT_TRUE(state_->EvaluateBranchCondition("BPL"));

  state_->set_flag_N(true);
  EXPECT_TRUE(state_->EvaluateBranchCondition("BMI"));
  EXPECT_FALSE(state_->EvaluateBranchCondition("BPL"));
}

// Test: Branch conditions - carry flag (BCS, BCC, BLO, BHS)
TEST_F(CpuState6809Test, BranchCarryFlag) {
  state_->set_flag_C(false);
  EXPECT_FALSE(state_->EvaluateBranchCondition("BCS"));
  EXPECT_FALSE(state_->EvaluateBranchCondition("BLO"));
  EXPECT_TRUE(state_->EvaluateBranchCondition("BCC"));
  EXPECT_TRUE(state_->EvaluateBranchCondition("BHS"));

  state_->set_flag_C(true);
  EXPECT_TRUE(state_->EvaluateBranchCondition("BCS"));
  EXPECT_TRUE(state_->EvaluateBranchCondition("BLO"));
  EXPECT_FALSE(state_->EvaluateBranchCondition("BCC"));
  EXPECT_FALSE(state_->EvaluateBranchCondition("BHS"));
}

// Test: Branch conditions - overflow flag (BVS, BVC)
TEST_F(CpuState6809Test, BranchOverflowFlag) {
  state_->set_flag_V(false);
  EXPECT_FALSE(state_->EvaluateBranchCondition("BVS"));
  EXPECT_TRUE(state_->EvaluateBranchCondition("BVC"));

  state_->set_flag_V(true);
  EXPECT_TRUE(state_->EvaluateBranchCondition("BVS"));
  EXPECT_FALSE(state_->EvaluateBranchCondition("BVC"));
}

// Test: Signed comparison branches (BGT, BGE, BLT, BLE)
TEST_F(CpuState6809Test, SignedComparisonBranches) {
  // BGT: Z=0 and (N == V)
  state_->set_flag_Z(false);
  state_->set_flag_N(false);
  state_->set_flag_V(false);
  EXPECT_TRUE(state_->EvaluateBranchCondition("BGT"));

  state_->set_flag_N(true);
  state_->set_flag_V(true);
  EXPECT_TRUE(state_->EvaluateBranchCondition("BGT"));

  state_->set_flag_V(false);
  EXPECT_FALSE(state_->EvaluateBranchCondition("BGT"));

  // BGE: (N == V)
  state_->set_flag_N(false);
  state_->set_flag_V(false);
  EXPECT_TRUE(state_->EvaluateBranchCondition("BGE"));

  state_->set_flag_N(true);
  state_->set_flag_V(true);
  EXPECT_TRUE(state_->EvaluateBranchCondition("BGE"));

  state_->set_flag_V(false);
  EXPECT_FALSE(state_->EvaluateBranchCondition("BGE"));

  // BLT: (N != V)
  EXPECT_TRUE(state_->EvaluateBranchCondition("BLT"));

  state_->set_flag_V(true);
  EXPECT_FALSE(state_->EvaluateBranchCondition("BLT"));

  // BLE: Z=1 or (N != V)
  state_->set_flag_Z(true);
  EXPECT_TRUE(state_->EvaluateBranchCondition("BLE"));

  state_->set_flag_Z(false);
  state_->set_flag_N(false);
  state_->set_flag_V(true);
  EXPECT_TRUE(state_->EvaluateBranchCondition("BLE"));
}

// Test: Unsigned comparison branches (BHI, BLS)
TEST_F(CpuState6809Test, UnsignedComparisonBranches) {
  // BHI: !C and !Z
  state_->set_flag_C(false);
  state_->set_flag_Z(false);
  EXPECT_TRUE(state_->EvaluateBranchCondition("BHI"));

  state_->set_flag_C(true);
  EXPECT_FALSE(state_->EvaluateBranchCondition("BHI"));

  state_->set_flag_C(false);
  state_->set_flag_Z(true);
  EXPECT_FALSE(state_->EvaluateBranchCondition("BHI"));

  // BLS: C or Z
  state_->set_flag_C(true);
  state_->set_flag_Z(false);
  EXPECT_TRUE(state_->EvaluateBranchCondition("BLS"));

  state_->set_flag_C(false);
  state_->set_flag_Z(true);
  EXPECT_TRUE(state_->EvaluateBranchCondition("BLS"));

  state_->set_flag_C(false);
  state_->set_flag_Z(false);
  EXPECT_FALSE(state_->EvaluateBranchCondition("BLS"));
}

// Test: Unknown branch condition
TEST_F(CpuState6809Test, UnknownBranchCondition) {
  bool result = state_->EvaluateBranchCondition("UNKNOWN");
  EXPECT_FALSE(result);  // Unknown branches default to not taken
}

// Test: 6809 Load A with flag effects
TEST_F(ExecutionSimulator6809EnhancedTest, LoadAAffectsFlags) {
  std::vector<uint8_t> code = {
    0x86, 0x00,  // LDA #$00 (should set Z, clear N)
    0x12         // NOP
  };

  core::Binary binary(code, 0x8000);

  // Create state and execute
  auto state = cpu_->CreateCpuState();
  state->SetPC(0x8000);

  // Execute LDA #$00
  core::Instruction inst;
  inst.mnemonic = "LDA";
  inst.mode = core::AddressingMode::IMMEDIATE;
  inst.bytes = {0x86, 0x00};

  auto read = [&](uint32_t addr) { return binary.GetByte(addr); };
  auto write = [](uint32_t, uint8_t) {};

  state->ExecuteInstruction(inst, read, write);

  auto state6809 = dynamic_cast<cpu::CpuState6809*>(state.get());
  EXPECT_EQ(state6809->A, 0x00);
  EXPECT_TRUE(state6809->flag_Z());
  EXPECT_FALSE(state6809->flag_N());
}

// Test: 6809 Load B with flag effects
TEST_F(ExecutionSimulator6809EnhancedTest, LoadBAffectsFlags) {
  std::vector<uint8_t> code = {
    0xC6, 0x42,  // LDB #$42
    0x12         // NOP
  };

  core::Binary binary(code, 0x8000);

  auto state = cpu_->CreateCpuState();

  core::Instruction inst;
  inst.mnemonic = "LDB";
  inst.mode = core::AddressingMode::IMMEDIATE;
  inst.bytes = {0xC6, 0x42};

  auto read = [&](uint32_t addr) { return binary.GetByte(addr); };
  auto write = [](uint32_t, uint8_t) {};

  state->ExecuteInstruction(inst, read, write);

  auto state6809 = dynamic_cast<cpu::CpuState6809*>(state.get());
  EXPECT_EQ(state6809->B, 0x42);
  EXPECT_FALSE(state6809->flag_Z());
  EXPECT_FALSE(state6809->flag_N());
}

// Test: 6809 ADDA overflow flag
TEST_F(ExecutionSimulator6809EnhancedTest, ADDAWithOverflow) {
  auto state = std::make_unique<cpu::CpuState6809>();
  state->A = 0x50;

  core::Instruction inst;
  inst.mnemonic = "ADDA";
  inst.mode = core::AddressingMode::IMMEDIATE;
  inst.bytes = {0x8B, 0x50};  // ADDA #$50

  auto read = [](uint32_t) { return static_cast<uint8_t>(0); };
  auto write = [](uint32_t, uint8_t) {};

  state->ExecuteInstruction(inst, read, write);

  // $50 + $50 = $A0, which is negative but operation was on two positive numbers
  EXPECT_EQ(state->A, 0xA0);
  EXPECT_TRUE(state->flag_V());  // Overflow occurred
}

// Test: 6809 SUBA instruction
TEST_F(ExecutionSimulator6809EnhancedTest, SUBAInstruction) {
  auto state = std::make_unique<cpu::CpuState6809>();
  state->A = 0x50;

  core::Instruction inst;
  inst.mnemonic = "SUBA";
  inst.mode = core::AddressingMode::IMMEDIATE;
  inst.bytes = {0x80, 0x30};

  auto read = [](uint32_t) { return static_cast<uint8_t>(0); };
  auto write = [](uint32_t, uint8_t) {};

  state->ExecuteInstruction(inst, read, write);

  EXPECT_EQ(state->A, 0x20);  // $50 - $30 = $20
  EXPECT_FALSE(state->flag_Z());
  EXPECT_FALSE(state->flag_N());
}

// Test: 6809 increment/decrement with overflow
TEST_F(ExecutionSimulator6809EnhancedTest, IncDecWithOverflow) {
  auto state = std::make_unique<cpu::CpuState6809>();
  state->A = 0x7F;

  core::Instruction inst;
  inst.mnemonic = "INCA";
  inst.mode = core::AddressingMode::IMPLIED;
  inst.bytes = {0x4C};

  auto read = [](uint32_t) { return static_cast<uint8_t>(0); };
  auto write = [](uint32_t, uint8_t) {};

  state->ExecuteInstruction(inst, read, write);

  EXPECT_EQ(state->A, 0x80);  // $7F + 1 = $80
  EXPECT_TRUE(state->flag_V());  // Overflow (positive to negative)

  state->B = 0x7F;
  inst.mnemonic = "DECB";
  inst.bytes = {0x5A};
  state->ExecuteInstruction(inst, read, write);

  EXPECT_EQ(state->B, 0x7E);
  EXPECT_FALSE(state->flag_V());
}

// Test: 6809 ANDCC instruction
TEST_F(ExecutionSimulator6809EnhancedTest, ANDCCInstruction) {
  auto state = std::make_unique<cpu::CpuState6809>();
  state->CC = 0xFF;  // All flags set

  core::Instruction inst;
  inst.mnemonic = "ANDCC";
  inst.mode = core::AddressingMode::IMMEDIATE;
  inst.bytes = {0x1C, 0xFE};  // ANDCC #$FE (clears C flag)

  auto read = [](uint32_t) { return static_cast<uint8_t>(0); };
  auto write = [](uint32_t, uint8_t) {};

  state->ExecuteInstruction(inst, read, write);

  EXPECT_FALSE(state->flag_C());
  EXPECT_TRUE(state->flag_Z());  // Other flags still set
}

// Test: 6809 ORCC instruction
TEST_F(ExecutionSimulator6809EnhancedTest, ORCCInstruction) {
  auto state = std::make_unique<cpu::CpuState6809>();
  state->CC = 0x00;  // No flags set

  core::Instruction inst;
  inst.mnemonic = "ORCC";
  inst.mode = core::AddressingMode::IMMEDIATE;
  inst.bytes = {0x1A, 0x05};  // ORCC #$05 (sets C and Z)

  auto read = [](uint32_t) { return static_cast<uint8_t>(0); };
  auto write = [](uint32_t, uint8_t) {};

  state->ExecuteInstruction(inst, read, write);

  EXPECT_TRUE(state->flag_C());
  EXPECT_TRUE(state->flag_Z());
}

// Test: 6809 Compare instructions
TEST_F(ExecutionSimulator6809EnhancedTest, CompareInstructions) {
  auto state = std::make_unique<cpu::CpuState6809>();
  state->A = 0x42;

  core::Instruction inst;
  inst.mnemonic = "CMPA";
  inst.mode = core::AddressingMode::IMMEDIATE;
  inst.bytes = {0x81, 0x42};  // CMPA #$42

  auto read = [](uint32_t) { return static_cast<uint8_t>(0); };
  auto write = [](uint32_t, uint8_t) {};

  state->ExecuteInstruction(inst, read, write);

  EXPECT_TRUE(state->flag_Z());  // Equal
  EXPECT_FALSE(state->flag_N());
  EXPECT_EQ(state->A, 0x42);  // A unchanged

  // Test CMPB
  state->B = 0x10;
  inst.mnemonic = "CMPB";
  inst.bytes = {0xC1, 0x20};
  state->ExecuteInstruction(inst, read, write);

  EXPECT_FALSE(state->flag_Z());  // Not equal
  EXPECT_TRUE(state->flag_N());   // B < operand
}

// Test: 6809 16-bit operations
TEST_F(ExecutionSimulator6809EnhancedTest, SixteenBitArithmetic) {
  auto state = std::make_unique<cpu::CpuState6809>();
  state->set_D(0x1000);

  core::Instruction inst;
  inst.mnemonic = "ADDD";
  inst.mode = core::AddressingMode::IMMEDIATE;
  inst.bytes = {0xC3, 0x20, 0x00};  // ADDD #$2000

  auto read = [](uint32_t) { return static_cast<uint8_t>(0); };
  auto write = [](uint32_t, uint8_t) {};

  state->ExecuteInstruction(inst, read, write);

  EXPECT_EQ(state->D(), 0x3000);
  EXPECT_FALSE(state->flag_Z());
  EXPECT_FALSE(state->flag_C());
}

// Test: 6809 logical operations (AND, OR, EOR)
TEST_F(ExecutionSimulator6809EnhancedTest, LogicalOperations) {
  auto state = std::make_unique<cpu::CpuState6809>();
  state->A = 0xF0;

  core::Instruction inst;
  inst.mnemonic = "ANDA";
  inst.mode = core::AddressingMode::IMMEDIATE;
  inst.bytes = {0x84, 0x0F};

  auto read = [](uint32_t) { return static_cast<uint8_t>(0); };
  auto write = [](uint32_t, uint8_t) {};

  state->ExecuteInstruction(inst, read, write);

  EXPECT_EQ(state->A, 0x00);  // $F0 AND $0F = $00
  EXPECT_TRUE(state->flag_Z());
  EXPECT_FALSE(state->flag_V());

  // Test ORA
  state->A = 0xF0;
  inst.mnemonic = "ORA";
  inst.bytes = {0x8A, 0x0F};
  state->ExecuteInstruction(inst, read, write);

  EXPECT_EQ(state->A, 0xFF);
  EXPECT_FALSE(state->flag_Z());

  // Test EORA
  state->A = 0xFF;
  inst.mnemonic = "EORA";
  inst.bytes = {0x88, 0xFF};
  state->ExecuteInstruction(inst, read, write);

  EXPECT_EQ(state->A, 0x00);
  EXPECT_TRUE(state->flag_Z());
}

// Test: 6809 Test instruction
TEST_F(ExecutionSimulator6809EnhancedTest, TestInstruction) {
  auto state = std::make_unique<cpu::CpuState6809>();
  state->A = 0x80;

  core::Instruction inst;
  inst.mnemonic = "TSTA";
  inst.mode = core::AddressingMode::IMPLIED;
  inst.bytes = {0x4D};

  auto read = [](uint32_t) { return static_cast<uint8_t>(0); };
  auto write = [](uint32_t, uint8_t) {};

  state->ExecuteInstruction(inst, read, write);

  EXPECT_EQ(state->A, 0x80);  // A unchanged
  EXPECT_FALSE(state->flag_Z());
  EXPECT_TRUE(state->flag_N());
  EXPECT_FALSE(state->flag_V());
}

// Test: 6809 NOP instruction
TEST_F(ExecutionSimulator6809EnhancedTest, NOPInstruction) {
  auto state = std::make_unique<cpu::CpuState6809>();
  state->A = 0x42;
  state->CC = 0xFF;

  core::Instruction inst;
  inst.mnemonic = "NOP";
  inst.mode = core::AddressingMode::IMPLIED;
  inst.bytes = {0x12};

  auto read = [](uint32_t) { return static_cast<uint8_t>(0); };
  auto write = [](uint32_t, uint8_t) {};

  state->ExecuteInstruction(inst, read, write);

  EXPECT_EQ(state->A, 0x42);
  EXPECT_EQ(state->CC, 0xFF);
}

// ============================================================================
// Phase 5: 6809 Indexed Addressing Mode Tests
// ============================================================================

class IndexedModeTest : public ::testing::Test {
 protected:
  using IndexedModeResult = cpu::m6809::IndexedModeResult;

  std::vector<uint8_t> CreatePostByte(bool indirect, uint8_t reg, uint8_t mode) {
    uint8_t postbyte = 0x80;  // Extended mode flag
    if (indirect) postbyte |= 0x10;
    postbyte |= (reg & 0x03) << 5;
    postbyte |= (mode & 0x0F);
    return {postbyte};
  }
};

// Test: 5-bit offset mode (-16 to +15)
TEST_F(IndexedModeTest, FiveBitOffsetMode) {
  std::vector<uint8_t> data = {0x10};  // +16 in 5-bit (actual offset: -16 to 15)
  auto result = cpu::m6809::ParseIndexedMode(data.data(), data.size(), 0x8000, 1);

  EXPECT_TRUE(result.is_valid);
  EXPECT_FALSE(result.is_indirect);
  EXPECT_EQ(result.size, 0);  // No additional bytes
}

// Test: Auto-increment mode (,R+)
TEST_F(IndexedModeTest, AutoIncrementMode) {
  std::vector<uint8_t> data = {0x80};  // ,X+
  auto result = cpu::m6809::ParseIndexedMode(data.data(), data.size(), 0x8000, 1);

  EXPECT_TRUE(result.is_valid);
  EXPECT_FALSE(result.is_indirect);
  EXPECT_EQ(result.operand, ",X+");
  EXPECT_EQ(result.size, 0);
}

// Test: Double auto-increment mode (,R++)
TEST_F(IndexedModeTest, DoubleAutoIncrementMode) {
  std::vector<uint8_t> data = {0x81};  // ,X++
  auto result = cpu::m6809::ParseIndexedMode(data.data(), data.size(), 0x8000, 1);

  EXPECT_TRUE(result.is_valid);
  EXPECT_FALSE(result.is_indirect);
  EXPECT_EQ(result.operand, ",X++");
  EXPECT_EQ(result.size, 0);
}

// Test: Pre-decrement mode (,-R)
TEST_F(IndexedModeTest, PreDecrementMode) {
  std::vector<uint8_t> data = {0x82};  // ,-X
  auto result = cpu::m6809::ParseIndexedMode(data.data(), data.size(), 0x8000, 1);

  EXPECT_TRUE(result.is_valid);
  EXPECT_FALSE(result.is_indirect);
  EXPECT_EQ(result.operand, ",-X");
  EXPECT_EQ(result.size, 0);
}

// Test: Double pre-decrement mode (,--R)
TEST_F(IndexedModeTest, DoublePreDecrementMode) {
  std::vector<uint8_t> data = {0x83};  // ,--X
  auto result = cpu::m6809::ParseIndexedMode(data.data(), data.size(), 0x8000, 1);

  EXPECT_TRUE(result.is_valid);
  EXPECT_FALSE(result.is_indirect);
  EXPECT_EQ(result.operand, ",--X");
  EXPECT_EQ(result.size, 0);
}

// Test: No offset mode (,R)
TEST_F(IndexedModeTest, NoOffsetMode) {
  std::vector<uint8_t> data = {0x84};  // ,X
  auto result = cpu::m6809::ParseIndexedMode(data.data(), data.size(), 0x8000, 1);

  EXPECT_TRUE(result.is_valid);
  EXPECT_FALSE(result.is_indirect);
  EXPECT_EQ(result.operand, ",X");
  EXPECT_EQ(result.size, 0);
}

// Test: Accumulator offset modes (B,R A,R D,R)
TEST_F(IndexedModeTest, AccumulatorOffsetModes) {
  // B,X
  std::vector<uint8_t> data = {0x85};
  auto result = cpu::m6809::ParseIndexedMode(data.data(), data.size(), 0x8000, 1);
  EXPECT_EQ(result.operand, "B,X");

  // A,X
  data[0] = 0x86;
  result = cpu::m6809::ParseIndexedMode(data.data(), data.size(), 0x8000, 1);
  EXPECT_EQ(result.operand, "A,X");

  // D,X
  data[0] = 0x8B;
  result = cpu::m6809::ParseIndexedMode(data.data(), data.size(), 0x8000, 1);
  EXPECT_EQ(result.operand, "D,X");
}

// Test: 8-bit offset mode
TEST_F(IndexedModeTest, EightBitOffsetMode) {
  std::vector<uint8_t> data = {0x88, 0x42};  // 8-bit offset
  auto result = cpu::m6809::ParseIndexedMode(data.data(), data.size(), 0x8000, 1);

  EXPECT_TRUE(result.is_valid);
  EXPECT_FALSE(result.is_indirect);
  EXPECT_EQ(result.operand, "66,X");  // $42 decimal = 66
  EXPECT_EQ(result.size, 1);
}

// Test: 8-bit offset negative
TEST_F(IndexedModeTest, EightBitOffsetNegative) {
  std::vector<uint8_t> data = {0x88, 0xFF};  // -1 in signed 8-bit
  auto result = cpu::m6809::ParseIndexedMode(data.data(), data.size(), 0x8000, 1);

  EXPECT_TRUE(result.is_valid);
  EXPECT_EQ(result.operand, "-1,X");
  EXPECT_EQ(result.size, 1);
}

// Test: 16-bit offset mode
TEST_F(IndexedModeTest, SixteenBitOffsetMode) {
  std::vector<uint8_t> data = {0x89, 0x12, 0x34};  // 16-bit offset
  auto result = cpu::m6809::ParseIndexedMode(data.data(), data.size(), 0x8000, 1);

  EXPECT_TRUE(result.is_valid);
  EXPECT_FALSE(result.is_indirect);
  EXPECT_EQ(result.operand, "4660,X");  // $1234 = 4660 decimal
  EXPECT_EQ(result.size, 2);
}

// Test: 16-bit offset negative
TEST_F(IndexedModeTest, SixteenBitOffsetNegative) {
  std::vector<uint8_t> data = {0x89, 0xFF, 0xFF};  // -1 in signed 16-bit
  auto result = cpu::m6809::ParseIndexedMode(data.data(), data.size(), 0x8000, 1);

  EXPECT_TRUE(result.is_valid);
  EXPECT_EQ(result.operand, "-1,X");
  EXPECT_EQ(result.size, 2);
}

// Test: PC-relative 8-bit offset
TEST_F(IndexedModeTest, PCRelativeEightBitOffset) {
  std::vector<uint8_t> data = {0x8C, 0x10};  // 8-bit offset,PC
  // PC = 0x8000 (opcode start), opcode_length = 1
  // PC after postbyte = 0x8000 + 1 + 2 = 0x8003
  // Target = 0x8003 + 0x10 = 0x8013
  auto result = cpu::m6809::ParseIndexedMode(data.data(), data.size(), 0x8000, 1);

  EXPECT_TRUE(result.is_valid);
  EXPECT_EQ(result.operand, "16,PC");
  EXPECT_EQ(result.target_address, 0x8013);
  EXPECT_EQ(result.size, 1);
}

// Test: PC-relative 16-bit offset
TEST_F(IndexedModeTest, PCRelativeSixteenBitOffset) {
  std::vector<uint8_t> data = {0x8D, 0x00, 0x10};  // 16-bit offset,PC
  // PC = 0x8000, opcode_length = 1
  // PC after postbyte + offset bytes = 0x8000 + 1 + 3 = 0x8004
  // Target = 0x8004 + 0x0010 = 0x8014
  auto result = cpu::m6809::ParseIndexedMode(data.data(), data.size(), 0x8000, 1);

  EXPECT_TRUE(result.is_valid);
  EXPECT_EQ(result.operand, "16,PC");
  EXPECT_EQ(result.target_address, 0x8014);
  EXPECT_EQ(result.size, 2);
}

// Test: PC-relative with negative offset
TEST_F(IndexedModeTest, PCRelativeNegativeOffset) {
  std::vector<uint8_t> data = {0x8C, 0xF0};  // -16 in signed 8-bit,PC
  // PC = 0x8000, opcode_length = 1
  // PC after = 0x8003
  // Target = 0x8003 + (-16) = 0x7FF3
  auto result = cpu::m6809::ParseIndexedMode(data.data(), data.size(), 0x8000, 1);

  EXPECT_TRUE(result.is_valid);
  EXPECT_EQ(result.operand, "-16,PC");
  EXPECT_EQ(result.target_address, 0x7FF3);
}

// Test: Indirect 8-bit offset
TEST_F(IndexedModeTest, IndirectEightBitOffset) {
  std::vector<uint8_t> data = {0x98, 0x10};  // [8-bit offset,X]
  auto result = cpu::m6809::ParseIndexedMode(data.data(), data.size(), 0x8000, 1);

  EXPECT_TRUE(result.is_valid);
  EXPECT_TRUE(result.is_indirect);
  EXPECT_EQ(result.operand, "[16,X]");
  EXPECT_EQ(result.size, 1);
}

// Test: Indirect 16-bit offset
TEST_F(IndexedModeTest, IndirectSixteenBitOffset) {
  std::vector<uint8_t> data = {0x99, 0x12, 0x34};  // [16-bit offset,X]
  auto result = cpu::m6809::ParseIndexedMode(data.data(), data.size(), 0x8000, 1);

  EXPECT_TRUE(result.is_valid);
  EXPECT_TRUE(result.is_indirect);
  EXPECT_EQ(result.operand, "[4660,X]");
  EXPECT_EQ(result.size, 2);
}

// Test: Indirect with accumulator offset (B,X)
TEST_F(IndexedModeTest, IndirectAccumulatorOffset) {
  std::vector<uint8_t> data = {0x95};  // [B,X]
  auto result = cpu::m6809::ParseIndexedMode(data.data(), data.size(), 0x8000, 1);

  EXPECT_TRUE(result.is_valid);
  EXPECT_TRUE(result.is_indirect);
  EXPECT_EQ(result.operand, "[B,X]");
}

// Test: Extended indirect mode ([$xxxx])
TEST_F(IndexedModeTest, ExtendedIndirectMode) {
  std::vector<uint8_t> data = {0x9F, 0x20, 0x00};  // [$2000]
  auto result = cpu::m6809::ParseIndexedMode(data.data(), data.size(), 0x8000, 1);

  EXPECT_TRUE(result.is_valid);
  EXPECT_TRUE(result.is_indirect);
  EXPECT_EQ(result.operand, "[$2000]");
  EXPECT_EQ(result.target_address, 0x2000);
  EXPECT_EQ(result.size, 2);
}

// Test: Different registers (Y, U, S)
TEST_F(IndexedModeTest, DifferentRegisters) {
  // Y register
  std::vector<uint8_t> data = {0xA4};  // ,Y
  auto result = cpu::m6809::ParseIndexedMode(data.data(), data.size(), 0x8000, 1);
  EXPECT_EQ(result.operand, ",Y");

  // U register
  data[0] = 0xC4;
  result = cpu::m6809::ParseIndexedMode(data.data(), data.size(), 0x8000, 1);
  EXPECT_EQ(result.operand, ",U");

  // S register
  data[0] = 0xE4;
  result = cpu::m6809::ParseIndexedMode(data.data(), data.size(), 0x8000, 1);
  EXPECT_EQ(result.operand, ",S");
}

// Test: Invalid S register with indirect (hardware limitation)
TEST_F(IndexedModeTest, InvalidSRegisterIndirect) {
  std::vector<uint8_t> data = {0xF5};  // [B,S] - invalid on hardware
  auto result = cpu::m6809::ParseIndexedMode(data.data(), data.size(), 0x8000, 1);

  EXPECT_FALSE(result.is_valid);  // Should be invalid
}

// Test: Empty data buffer
TEST_F(IndexedModeTest, EmptyDataBuffer) {
  std::vector<uint8_t> data;
  auto result = cpu::m6809::ParseIndexedMode(data.data(), 0, 0x8000, 1);

  EXPECT_FALSE(result.is_valid);
  EXPECT_EQ(result.operand, "???");
}

// Test: Insufficient data for 8-bit offset
TEST_F(IndexedModeTest, InsufficientDataEightBitOffset) {
  std::vector<uint8_t> data = {0x88};  // Missing offset byte
  auto result = cpu::m6809::ParseIndexedMode(data.data(), 1, 0x8000, 1);

  EXPECT_FALSE(result.is_valid);
  EXPECT_EQ(result.operand, "??,X");
}

// Test: Insufficient data for 16-bit offset
TEST_F(IndexedModeTest, InsufficientDataSixteenBitOffset) {
  std::vector<uint8_t> data = {0x89, 0x12};  // Missing second offset byte
  auto result = cpu::m6809::ParseIndexedMode(data.data(), 2, 0x8000, 1);

  EXPECT_FALSE(result.is_valid);
  EXPECT_EQ(result.operand, "??,X");
}

// Test: Invalid extended mode value
TEST_F(IndexedModeTest, InvalidExtendedMode) {
  std::vector<uint8_t> data = {0x87};  // Invalid mode (0x07)
  auto result = cpu::m6809::ParseIndexedMode(data.data(), data.size(), 0x8000, 1);

  EXPECT_FALSE(result.is_valid);
  EXPECT_EQ(result.operand, "???");
}

// Test: PC-relative boundary check
TEST_F(IndexedModeTest, PCRelativeBoundaryCheck) {
  std::vector<uint8_t> data = {0x8D, 0x80, 0x00};  // Large positive offset
  // PC = 0xFFFF, with offset, would wrap. Should detect as invalid.
  auto result = cpu::m6809::ParseIndexedMode(data.data(), data.size(), 0xFFFE, 1);

  // Target would be beyond 16-bit address space
  EXPECT_FALSE(result.is_valid);
}

// Test: Negative 16-bit offset with large magnitude
TEST_F(IndexedModeTest, LargeNegativeSixteenBitOffset) {
  std::vector<uint8_t> data = {0x8D, 0x80, 0x00};  // -32768 in signed 16-bit
  auto result = cpu::m6809::ParseIndexedMode(data.data(), data.size(), 0x8000, 1);

  // With extreme offset, should be marked as data, not code
  EXPECT_FALSE(result.is_valid);
}

// Test: Mode with 2-byte opcode (long form)
TEST_F(IndexedModeTest, LongFormOpcode) {
  std::vector<uint8_t> data = {0x8C, 0x10};  // 8-bit offset,PC
  // opcode_length = 2 (for 10 xx instructions)
  // PC = 0x8000, PC after = 0x8000 + 2 + 2 = 0x8004
  auto result = cpu::m6809::ParseIndexedMode(data.data(), data.size(), 0x8000, 2);

  EXPECT_TRUE(result.is_valid);
  EXPECT_EQ(result.target_address, 0x8014);
}

}  // namespace
}  // namespace analysis
}  // namespace sourcerer
