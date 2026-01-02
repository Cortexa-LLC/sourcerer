// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "core/instruction.h"

#include <gtest/gtest.h>

namespace sourcerer {
namespace core {
namespace {

// Test fixture for Instruction struct
class InstructionTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Default instruction for testing
    inst_.address = 0x8000;
    inst_.bytes = {0xA9, 0x00};  // LDA #$00
    inst_.mnemonic = "LDA";
    inst_.operand = "#$00";
    inst_.mode = AddressingMode::IMMEDIATE;
    inst_.target_address = 0;
    inst_.is_branch = false;
    inst_.is_jump = false;
    inst_.is_call = false;
    inst_.is_return = false;
    inst_.is_illegal = false;
  }

  Instruction inst_;
};

// Test default constructor
TEST_F(InstructionTest, DefaultConstructor) {
  Instruction inst;
  EXPECT_EQ(inst.address, 0);
  EXPECT_TRUE(inst.bytes.empty());
  EXPECT_TRUE(inst.mnemonic.empty());
  EXPECT_TRUE(inst.operand.empty());
  EXPECT_EQ(inst.mode, AddressingMode::UNKNOWN);
  EXPECT_EQ(inst.target_address, 0);
  EXPECT_FALSE(inst.is_branch);
  EXPECT_FALSE(inst.is_jump);
  EXPECT_FALSE(inst.is_call);
  EXPECT_FALSE(inst.is_return);
  EXPECT_FALSE(inst.is_illegal);
}

// Test Size() method
TEST_F(InstructionTest, Size) {
  EXPECT_EQ(inst_.Size(), 2);

  inst_.bytes = {0xEA};  // NOP (1 byte)
  EXPECT_EQ(inst_.Size(), 1);

  inst_.bytes = {0x20, 0x00, 0x80};  // JSR $8000 (3 bytes)
  EXPECT_EQ(inst_.Size(), 3);
}

// Test HasTarget() method
TEST_F(InstructionTest, HasTarget) {
  EXPECT_FALSE(inst_.HasTarget());

  inst_.target_address = 0x8010;
  EXPECT_TRUE(inst_.HasTarget());
}

// Test ToString() method
TEST_F(InstructionTest, ToString) {
  EXPECT_EQ(inst_.ToString(), "LDA #$00");

  inst_.mnemonic = "RTS";
  inst_.operand = "";
  EXPECT_EQ(inst_.ToString(), "RTS");

  inst_.mnemonic = "BNE";
  inst_.operand = "LOOP";
  EXPECT_EQ(inst_.ToString(), "BNE LOOP");
}

// Test immediate addressing mode
TEST_F(InstructionTest, ImmediateMode) {
  inst_.bytes = {0xA9, 0xFF};
  inst_.mnemonic = "LDA";
  inst_.operand = "#$FF";
  inst_.mode = AddressingMode::IMMEDIATE;

  EXPECT_EQ(inst_.Size(), 2);
  EXPECT_EQ(inst_.ToString(), "LDA #$FF");
}

// Test zero page addressing
TEST_F(InstructionTest, ZeroPageMode) {
  inst_.bytes = {0xA5, 0x10};
  inst_.mnemonic = "LDA";
  inst_.operand = "$10";
  inst_.mode = AddressingMode::ZERO_PAGE;

  EXPECT_EQ(inst_.Size(), 2);
  EXPECT_EQ(inst_.ToString(), "LDA $10");
}

// Test absolute addressing
TEST_F(InstructionTest, AbsoluteMode) {
  inst_.bytes = {0xAD, 0x00, 0x80};
  inst_.mnemonic = "LDA";
  inst_.operand = "$8000";
  inst_.mode = AddressingMode::ABSOLUTE;

  EXPECT_EQ(inst_.Size(), 3);
  EXPECT_EQ(inst_.ToString(), "LDA $8000");
}

// Test branch instruction
TEST_F(InstructionTest, BranchInstruction) {
  inst_.bytes = {0xD0, 0xFE};  // BNE -2
  inst_.mnemonic = "BNE";
  inst_.operand = "LOOP";
  inst_.mode = AddressingMode::RELATIVE;
  inst_.target_address = 0x8000;
  inst_.is_branch = true;

  EXPECT_TRUE(inst_.is_branch);
  EXPECT_FALSE(inst_.is_jump);
  EXPECT_FALSE(inst_.is_call);
  EXPECT_TRUE(inst_.HasTarget());
}

// Test jump instruction
TEST_F(InstructionTest, JumpInstruction) {
  inst_.bytes = {0x4C, 0x00, 0x90};  // JMP $9000
  inst_.mnemonic = "JMP";
  inst_.operand = "$9000";
  inst_.mode = AddressingMode::ABSOLUTE;
  inst_.target_address = 0x9000;
  inst_.is_jump = true;

  EXPECT_FALSE(inst_.is_branch);
  EXPECT_TRUE(inst_.is_jump);
  EXPECT_FALSE(inst_.is_call);
  EXPECT_TRUE(inst_.HasTarget());
}

// Test subroutine call
TEST_F(InstructionTest, CallInstruction) {
  inst_.bytes = {0x20, 0x00, 0x90};  // JSR $9000
  inst_.mnemonic = "JSR";
  inst_.operand = "$9000";
  inst_.mode = AddressingMode::ABSOLUTE;
  inst_.target_address = 0x9000;
  inst_.is_call = true;

  EXPECT_FALSE(inst_.is_branch);
  EXPECT_FALSE(inst_.is_jump);
  EXPECT_TRUE(inst_.is_call);
  EXPECT_TRUE(inst_.HasTarget());
}

// Test return instruction
TEST_F(InstructionTest, ReturnInstruction) {
  inst_.bytes = {0x60};  // RTS
  inst_.mnemonic = "RTS";
  inst_.operand = "";
  inst_.mode = AddressingMode::IMPLIED;
  inst_.is_return = true;

  EXPECT_FALSE(inst_.is_branch);
  EXPECT_FALSE(inst_.is_jump);
  EXPECT_FALSE(inst_.is_call);
  EXPECT_TRUE(inst_.is_return);
  EXPECT_FALSE(inst_.HasTarget());
}

// Test implied addressing mode
TEST_F(InstructionTest, ImpliedMode) {
  inst_.bytes = {0xEA};  // NOP
  inst_.mnemonic = "NOP";
  inst_.operand = "";
  inst_.mode = AddressingMode::IMPLIED;

  EXPECT_EQ(inst_.Size(), 1);
  EXPECT_EQ(inst_.ToString(), "NOP");
}

// Test indexed addressing modes
TEST_F(InstructionTest, IndexedModes) {
  // Zero page X
  inst_.bytes = {0xB5, 0x10};
  inst_.mnemonic = "LDA";
  inst_.operand = "$10,X";
  inst_.mode = AddressingMode::ZERO_PAGE_X;
  EXPECT_EQ(inst_.ToString(), "LDA $10,X");

  // Absolute X
  inst_.bytes = {0xBD, 0x00, 0x80};
  inst_.operand = "$8000,X";
  inst_.mode = AddressingMode::ABSOLUTE_X;
  EXPECT_EQ(inst_.ToString(), "LDA $8000,X");

  // Absolute Y
  inst_.bytes = {0xB9, 0x00, 0x80};
  inst_.operand = "$8000,Y";
  inst_.mode = AddressingMode::ABSOLUTE_Y;
  EXPECT_EQ(inst_.ToString(), "LDA $8000,Y");
}

// Test indirect addressing modes
TEST_F(InstructionTest, IndirectModes) {
  // Indirect (JMP only)
  inst_.bytes = {0x6C, 0x00, 0x80};
  inst_.mnemonic = "JMP";
  inst_.operand = "($8000)";
  inst_.mode = AddressingMode::INDIRECT;
  EXPECT_EQ(inst_.ToString(), "JMP ($8000)");

  // Indexed indirect
  inst_.bytes = {0xA1, 0x10};
  inst_.mnemonic = "LDA";
  inst_.operand = "($10,X)";
  inst_.mode = AddressingMode::INDEXED_INDIRECT;
  EXPECT_EQ(inst_.ToString(), "LDA ($10,X)");

  // Indirect indexed
  inst_.bytes = {0xB1, 0x10};
  inst_.operand = "($10),Y";
  inst_.mode = AddressingMode::INDIRECT_INDEXED;
  EXPECT_EQ(inst_.ToString(), "LDA ($10),Y");
}

// Test 65C02 addressing mode
TEST_F(InstructionTest, Mode65C02) {
  inst_.bytes = {0x7C, 0x00, 0x80};  // JMP ($8000,X)
  inst_.mnemonic = "JMP";
  inst_.operand = "($8000,X)";
  inst_.mode = AddressingMode::ABSOLUTE_INDEXED_INDIRECT;
  EXPECT_EQ(inst_.ToString(), "JMP ($8000,X)");
}

// Test illegal opcode
TEST_F(InstructionTest, IllegalOpcode) {
  inst_.bytes = {0xEB};  // Unofficial SBC immediate
  inst_.mnemonic = "SBC";
  inst_.operand = "#$00";
  inst_.is_illegal = true;

  EXPECT_TRUE(inst_.is_illegal);
}

// Test instruction with comment
TEST_F(InstructionTest, InstructionWithComment) {
  inst_.comment = "Initialize accumulator";
  EXPECT_EQ(inst_.comment, "Initialize accumulator");
}

// Test relative branch target calculation
TEST_F(InstructionTest, RelativeBranchTarget) {
  // BNE $8010 (from $8000)
  inst_.address = 0x8000;
  inst_.bytes = {0xD0, 0x0E};  // BNE +14 (forward)
  inst_.mnemonic = "BNE";
  inst_.mode = AddressingMode::RELATIVE;
  inst_.is_branch = true;
  inst_.target_address = 0x8010;  // $8000 + 2 + 14 = $8010

  EXPECT_EQ(inst_.target_address, 0x8010);

  // BNE $7FF0 (from $8000)
  inst_.bytes = {0xD0, 0xEE};  // BNE -18 (backward)
  inst_.target_address = 0x7FF0;  // $8000 + 2 - 18 = $7FF0

  EXPECT_EQ(inst_.target_address, 0x7FF0);
}

// Test accumulator addressing mode
TEST_F(InstructionTest, AccumulatorMode) {
  inst_.bytes = {0x0A};  // ASL A
  inst_.mnemonic = "ASL";
  inst_.operand = "A";
  inst_.mode = AddressingMode::ACCUMULATOR;

  EXPECT_EQ(inst_.Size(), 1);
  EXPECT_EQ(inst_.ToString(), "ASL A");
}

}  // namespace
}  // namespace core
}  // namespace sourcerer
