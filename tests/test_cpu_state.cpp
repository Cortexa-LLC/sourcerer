// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include <gtest/gtest.h>

#include "cpu/m6502/cpu_state_6502.h"
#include "cpu/m6809/cpu_state_6809.h"

namespace sourcerer {
namespace cpu {
namespace {

// ===== 6809 CPU State Tests =====

class CpuState6809Test : public ::testing::Test {
 protected:
  void SetUp() override {
    state_ = std::make_unique<CpuState6809>();
  }

  std::unique_ptr<CpuState6809> state_;
};

TEST_F(CpuState6809Test, InitialState) {
  EXPECT_EQ(state_->A, 0);
  EXPECT_EQ(state_->B, 0);
  EXPECT_EQ(state_->X, 0);
  EXPECT_EQ(state_->Y, 0);
  EXPECT_EQ(state_->PC, 0);
  EXPECT_EQ(state_->CC, 0);
}

TEST_F(CpuState6809Test, PCAccessors) {
  state_->SetPC(0x8000);
  EXPECT_EQ(state_->GetPC(), 0x8000);
  EXPECT_EQ(state_->PC, 0x8000);
}

TEST_F(CpuState6809Test, Reset) {
  state_->A = 0xFF;
  state_->PC = 0x8000;
  state_->CC = 0xFF;

  state_->Reset();

  EXPECT_EQ(state_->A, 0);
  EXPECT_EQ(state_->PC, 0);
  EXPECT_EQ(state_->CC, 0);
}

TEST_F(CpuState6809Test, FlagAccessors) {
  state_->CC = 0;
  EXPECT_FALSE(state_->flag_C());
  EXPECT_FALSE(state_->flag_Z());
  EXPECT_FALSE(state_->flag_N());
  EXPECT_FALSE(state_->flag_V());

  state_->set_flag_Z(true);
  EXPECT_TRUE(state_->flag_Z());
  EXPECT_EQ(state_->CC & 0x04, 0x04);

  state_->set_flag_N(true);
  EXPECT_TRUE(state_->flag_N());
  EXPECT_EQ(state_->CC & 0x08, 0x08);
}

TEST_F(CpuState6809Test, DRegister) {
  state_->set_D(0x1234);
  EXPECT_EQ(state_->A, 0x12);
  EXPECT_EQ(state_->B, 0x34);
  EXPECT_EQ(state_->D(), 0x1234);
}

TEST_F(CpuState6809Test, BranchAlways) {
  EXPECT_TRUE(state_->EvaluateBranchCondition("BRA"));
  EXPECT_TRUE(state_->EvaluateBranchCondition("LBRA"));
}

TEST_F(CpuState6809Test, BranchOnZero) {
  state_->set_flag_Z(true);
  EXPECT_TRUE(state_->EvaluateBranchCondition("BEQ"));
  EXPECT_TRUE(state_->EvaluateBranchCondition("LBEQ"));
  EXPECT_FALSE(state_->EvaluateBranchCondition("BNE"));
  EXPECT_FALSE(state_->EvaluateBranchCondition("LBNE"));

  state_->set_flag_Z(false);
  EXPECT_FALSE(state_->EvaluateBranchCondition("BEQ"));
  EXPECT_TRUE(state_->EvaluateBranchCondition("BNE"));
}

TEST_F(CpuState6809Test, BranchOnNegative) {
  state_->set_flag_N(true);
  EXPECT_TRUE(state_->EvaluateBranchCondition("BMI"));
  EXPECT_FALSE(state_->EvaluateBranchCondition("BPL"));

  state_->set_flag_N(false);
  EXPECT_FALSE(state_->EvaluateBranchCondition("BMI"));
  EXPECT_TRUE(state_->EvaluateBranchCondition("BPL"));
}

TEST_F(CpuState6809Test, BranchOnCarry) {
  state_->set_flag_C(true);
  EXPECT_TRUE(state_->EvaluateBranchCondition("BCS"));
  EXPECT_TRUE(state_->EvaluateBranchCondition("BLO"));
  EXPECT_FALSE(state_->EvaluateBranchCondition("BCC"));
  EXPECT_FALSE(state_->EvaluateBranchCondition("BHS"));

  state_->set_flag_C(false);
  EXPECT_FALSE(state_->EvaluateBranchCondition("BCS"));
  EXPECT_TRUE(state_->EvaluateBranchCondition("BCC"));
}

TEST_F(CpuState6809Test, BranchSignedComparisons) {
  // BGT: !Z && (N == V)
  state_->CC = 0;
  state_->set_flag_Z(false);
  state_->set_flag_N(false);
  state_->set_flag_V(false);
  EXPECT_TRUE(state_->EvaluateBranchCondition("BGT"));

  state_->set_flag_Z(true);
  EXPECT_FALSE(state_->EvaluateBranchCondition("BGT"));

  // BGE: N == V
  state_->CC = 0;
  state_->set_flag_N(false);
  state_->set_flag_V(false);
  EXPECT_TRUE(state_->EvaluateBranchCondition("BGE"));

  state_->set_flag_N(true);
  state_->set_flag_V(true);
  EXPECT_TRUE(state_->EvaluateBranchCondition("BGE"));

  state_->set_flag_N(true);
  state_->set_flag_V(false);
  EXPECT_FALSE(state_->EvaluateBranchCondition("BGE"));
}

// ===== 6502 CPU State Tests =====

class CpuState6502Test : public ::testing::Test {
 protected:
  void SetUp() override {
    state_ = std::make_unique<CpuState6502>();
  }

  std::unique_ptr<CpuState6502> state_;
};

TEST_F(CpuState6502Test, InitialState) {
  EXPECT_EQ(state_->A, 0);
  EXPECT_EQ(state_->X, 0);
  EXPECT_EQ(state_->Y, 0);
  EXPECT_EQ(state_->PC, 0);
  EXPECT_EQ(state_->P, 0);
}

TEST_F(CpuState6502Test, PCAccessors) {
  state_->SetPC(0x2000);
  EXPECT_EQ(state_->GetPC(), 0x2000);
  EXPECT_EQ(state_->PC, 0x2000);
}

TEST_F(CpuState6502Test, Reset) {
  state_->A = 0xFF;
  state_->PC = 0x8000;
  state_->P = 0xFF;

  state_->Reset();

  EXPECT_EQ(state_->A, 0);
  EXPECT_EQ(state_->PC, 0);
  EXPECT_EQ(state_->SP, 0xFF);
  EXPECT_EQ(state_->P, 0x20);  // Bit 5 always set
}

TEST_F(CpuState6502Test, FlagAccessors) {
  state_->P = 0;
  EXPECT_FALSE(state_->flag_C());
  EXPECT_FALSE(state_->flag_Z());
  EXPECT_FALSE(state_->flag_N());
  EXPECT_FALSE(state_->flag_V());

  state_->set_flag_Z(true);
  EXPECT_TRUE(state_->flag_Z());
  EXPECT_EQ(state_->P & 0x02, 0x02);

  state_->set_flag_N(true);
  EXPECT_TRUE(state_->flag_N());
  EXPECT_EQ(state_->P & 0x80, 0x80);
}

TEST_F(CpuState6502Test, BranchOnCarry) {
  state_->set_flag_C(true);
  EXPECT_TRUE(state_->EvaluateBranchCondition("BCS"));
  EXPECT_FALSE(state_->EvaluateBranchCondition("BCC"));

  state_->set_flag_C(false);
  EXPECT_FALSE(state_->EvaluateBranchCondition("BCS"));
  EXPECT_TRUE(state_->EvaluateBranchCondition("BCC"));
}

TEST_F(CpuState6502Test, BranchOnZero) {
  state_->set_flag_Z(true);
  EXPECT_TRUE(state_->EvaluateBranchCondition("BEQ"));
  EXPECT_FALSE(state_->EvaluateBranchCondition("BNE"));

  state_->set_flag_Z(false);
  EXPECT_FALSE(state_->EvaluateBranchCondition("BEQ"));
  EXPECT_TRUE(state_->EvaluateBranchCondition("BNE"));
}

TEST_F(CpuState6502Test, BranchOnNegative) {
  state_->set_flag_N(true);
  EXPECT_TRUE(state_->EvaluateBranchCondition("BMI"));
  EXPECT_FALSE(state_->EvaluateBranchCondition("BPL"));

  state_->set_flag_N(false);
  EXPECT_FALSE(state_->EvaluateBranchCondition("BMI"));
  EXPECT_TRUE(state_->EvaluateBranchCondition("BPL"));
}

TEST_F(CpuState6502Test, BranchOnOverflow) {
  state_->set_flag_V(true);
  EXPECT_TRUE(state_->EvaluateBranchCondition("BVS"));
  EXPECT_FALSE(state_->EvaluateBranchCondition("BVC"));

  state_->set_flag_V(false);
  EXPECT_FALSE(state_->EvaluateBranchCondition("BVS"));
  EXPECT_TRUE(state_->EvaluateBranchCondition("BVC"));
}

TEST_F(CpuState6502Test, BranchAlways65C02) {
  EXPECT_TRUE(state_->EvaluateBranchCondition("BRA"));
}

TEST_F(CpuState6502Test, UnknownBranch) {
  // Unknown branches return false for safety
  EXPECT_FALSE(state_->EvaluateBranchCondition("UNKNOWN"));
}

}  // namespace
}  // namespace cpu
}  // namespace sourcerer
