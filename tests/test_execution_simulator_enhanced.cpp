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

}  // namespace
}  // namespace analysis
}  // namespace sourcerer
