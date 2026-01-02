// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "cpu/m6502/cpu_6502.h"

#include <gtest/gtest.h>

namespace sourcerer {
namespace cpu {
namespace m6502 {
namespace {

// Test fixture for 6502 CPU tests
class Cpu6502Test : public ::testing::Test {
 protected:
  void SetUp() override {
    cpu_ = std::make_unique<Cpu6502>(CpuVariant::MOS_6502);
  }

  std::unique_ptr<Cpu6502> cpu_;
};

// Test plugin metadata
TEST_F(Cpu6502Test, PluginMetadata) {
  EXPECT_EQ(cpu_->Name(), "6502");
  EXPECT_EQ(cpu_->GetVariant(), CpuVariant::MOS_6502);
  EXPECT_FALSE(cpu_->Supports16Bit());
  EXPECT_EQ(cpu_->MaxAddress(), 0xFFFF);
  EXPECT_EQ(cpu_->AddressMask(), 0xFFFF);

  std::vector<std::string> aliases = cpu_->Aliases();
  EXPECT_GT(aliases.size(), 0);
}

// Test immediate addressing mode
TEST_F(Cpu6502Test, ImmediateMode) {
  uint8_t code[] = {0xA9, 0x00};  // LDA #$00
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.address, 0x8000);
  EXPECT_EQ(inst.mnemonic, "LDA");
  EXPECT_EQ(inst.operand, "#$00");
  EXPECT_EQ(inst.mode, core::AddressingMode::IMMEDIATE);
  EXPECT_EQ(inst.Size(), 2);
  EXPECT_EQ(inst.bytes[0], 0xA9);
  EXPECT_EQ(inst.bytes[1], 0x00);
  EXPECT_FALSE(inst.is_branch);
  EXPECT_FALSE(inst.is_jump);
  EXPECT_FALSE(inst.is_call);
}

// Test zero page addressing
TEST_F(Cpu6502Test, ZeroPageMode) {
  uint8_t code[] = {0xA5, 0x10};  // LDA $10
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "LDA");
  EXPECT_EQ(inst.operand, "$10");
  EXPECT_EQ(inst.mode, core::AddressingMode::ZERO_PAGE);
  EXPECT_EQ(inst.Size(), 2);
}

// Test zero page X addressing
TEST_F(Cpu6502Test, ZeroPageXMode) {
  uint8_t code[] = {0xB5, 0x10};  // LDA $10,X
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "LDA");
  EXPECT_EQ(inst.operand, "$10,X");
  EXPECT_EQ(inst.mode, core::AddressingMode::ZERO_PAGE_X);
  EXPECT_EQ(inst.Size(), 2);
}

// Test absolute addressing
TEST_F(Cpu6502Test, AbsoluteMode) {
  uint8_t code[] = {0xAD, 0x00, 0x80};  // LDA $8000
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "LDA");
  EXPECT_EQ(inst.operand, "$8000");
  EXPECT_EQ(inst.mode, core::AddressingMode::ABSOLUTE);
  EXPECT_EQ(inst.Size(), 3);
}

// Test absolute X addressing
TEST_F(Cpu6502Test, AbsoluteXMode) {
  uint8_t code[] = {0xBD, 0x00, 0x80};  // LDA $8000,X
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "LDA");
  EXPECT_EQ(inst.operand, "$8000,X");
  EXPECT_EQ(inst.mode, core::AddressingMode::ABSOLUTE_X);
  EXPECT_EQ(inst.Size(), 3);
}

// Test absolute Y addressing
TEST_F(Cpu6502Test, AbsoluteYMode) {
  uint8_t code[] = {0xB9, 0x00, 0x80};  // LDA $8000,Y
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "LDA");
  EXPECT_EQ(inst.operand, "$8000,Y");
  EXPECT_EQ(inst.mode, core::AddressingMode::ABSOLUTE_Y);
  EXPECT_EQ(inst.Size(), 3);
}

// Test indexed indirect addressing (X)
TEST_F(Cpu6502Test, IndexedIndirectMode) {
  uint8_t code[] = {0xA1, 0x10};  // LDA ($10,X)
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "LDA");
  EXPECT_EQ(inst.operand, "($10,X)");
  EXPECT_EQ(inst.mode, core::AddressingMode::INDEXED_INDIRECT);
  EXPECT_EQ(inst.Size(), 2);
}

// Test indirect indexed addressing (Y)
TEST_F(Cpu6502Test, IndirectIndexedMode) {
  uint8_t code[] = {0xB1, 0x10};  // LDA ($10),Y
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "LDA");
  EXPECT_EQ(inst.operand, "($10),Y");
  EXPECT_EQ(inst.mode, core::AddressingMode::INDIRECT_INDEXED);
  EXPECT_EQ(inst.Size(), 2);
}

// Test implied addressing
TEST_F(Cpu6502Test, ImpliedMode) {
  uint8_t code[] = {0xEA};  // NOP
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "NOP");
  EXPECT_TRUE(inst.operand.empty());
  EXPECT_EQ(inst.mode, core::AddressingMode::IMPLIED);
  EXPECT_EQ(inst.Size(), 1);
}

// Test accumulator addressing
TEST_F(Cpu6502Test, AccumulatorMode) {
  uint8_t code[] = {0x0A};  // ASL A
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "ASL");
  // Accumulator mode may have empty operand or "A" depending on assembler convention
  // Our implementation uses empty operand for accumulator mode
  EXPECT_TRUE(inst.operand.empty() || inst.operand == "A");
  EXPECT_EQ(inst.mode, core::AddressingMode::ACCUMULATOR);
  EXPECT_EQ(inst.Size(), 1);
}

// Test branch instructions (forward)
TEST_F(Cpu6502Test, BranchForward) {
  uint8_t code[] = {0xD0, 0x0E};  // BNE +14
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "BNE");
  EXPECT_EQ(inst.mode, core::AddressingMode::RELATIVE);
  EXPECT_TRUE(inst.is_branch);
  EXPECT_FALSE(inst.is_jump);
  EXPECT_EQ(inst.target_address, 0x8010);  // 0x8000 + 2 + 14 = 0x8010
  EXPECT_EQ(inst.Size(), 2);
}

// Test branch instructions (backward)
TEST_F(Cpu6502Test, BranchBackward) {
  uint8_t code[] = {0xD0, 0xFE};  // BNE -2 (branch to self)
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "BNE");
  EXPECT_TRUE(inst.is_branch);
  EXPECT_EQ(inst.target_address, 0x8000);  // Branch to itself
}

// Test jump absolute
TEST_F(Cpu6502Test, JumpAbsolute) {
  uint8_t code[] = {0x4C, 0x00, 0x90};  // JMP $9000
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "JMP");
  EXPECT_EQ(inst.operand, "$9000");
  EXPECT_EQ(inst.mode, core::AddressingMode::ABSOLUTE);
  EXPECT_TRUE(inst.is_jump);
  EXPECT_FALSE(inst.is_branch);
  EXPECT_FALSE(inst.is_call);
  EXPECT_EQ(inst.target_address, 0x9000);
  EXPECT_EQ(inst.Size(), 3);
}

// Test jump indirect
TEST_F(Cpu6502Test, JumpIndirect) {
  uint8_t code[] = {0x6C, 0x00, 0x80};  // JMP ($8000)
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "JMP");
  EXPECT_EQ(inst.operand, "($8000)");
  EXPECT_EQ(inst.mode, core::AddressingMode::INDIRECT);
  EXPECT_TRUE(inst.is_jump);
  EXPECT_EQ(inst.Size(), 3);
}

// Test JSR (subroutine call)
TEST_F(Cpu6502Test, SubroutineCall) {
  uint8_t code[] = {0x20, 0x10, 0x80};  // JSR $8010
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "JSR");
  EXPECT_EQ(inst.operand, "$8010");
  EXPECT_TRUE(inst.is_call);
  EXPECT_FALSE(inst.is_branch);
  EXPECT_FALSE(inst.is_jump);
  EXPECT_EQ(inst.target_address, 0x8010);
  EXPECT_EQ(inst.Size(), 3);
}

// Test RTS (return from subroutine)
TEST_F(Cpu6502Test, ReturnFromSubroutine) {
  uint8_t code[] = {0x60};  // RTS
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "RTS");
  EXPECT_TRUE(inst.is_return);
  EXPECT_FALSE(inst.is_call);
  EXPECT_FALSE(inst.is_branch);
  EXPECT_FALSE(inst.is_jump);
  EXPECT_EQ(inst.Size(), 1);
}

// Test RTI (return from interrupt)
TEST_F(Cpu6502Test, ReturnFromInterrupt) {
  uint8_t code[] = {0x40};  // RTI
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "RTI");
  EXPECT_TRUE(inst.is_return);
  EXPECT_EQ(inst.Size(), 1);
}

// Test GetInstructionSize
TEST_F(Cpu6502Test, GetInstructionSize) {
  uint8_t code1[] = {0xEA};              // NOP - 1 byte
  uint8_t code2[] = {0xA9, 0x00};        // LDA # - 2 bytes
  uint8_t code3[] = {0x4C, 0x00, 0x90};  // JMP $ - 3 bytes

  EXPECT_EQ(cpu_->GetInstructionSize(code1, sizeof(code1), 0x8000), 1);
  EXPECT_EQ(cpu_->GetInstructionSize(code2, sizeof(code2), 0x8000), 2);
  EXPECT_EQ(cpu_->GetInstructionSize(code3, sizeof(code3), 0x8000), 3);
}

// Test multiple sequential instructions
TEST_F(Cpu6502Test, SequentialInstructions) {
  uint8_t code[] = {
      0xA9, 0x00,        // LDA #$00
      0x85, 0x10,        // STA $10
      0xEA,              // NOP
      0x4C, 0x00, 0x90   // JMP $9000
  };

  // Disassemble first instruction
  core::Instruction inst1 = cpu_->Disassemble(code, sizeof(code), 0x8000);
  EXPECT_EQ(inst1.mnemonic, "LDA");
  EXPECT_EQ(inst1.Size(), 2);

  // Disassemble second instruction
  core::Instruction inst2 = cpu_->Disassemble(code + 2, sizeof(code) - 2, 0x8002);
  EXPECT_EQ(inst2.mnemonic, "STA");
  EXPECT_EQ(inst2.Size(), 2);

  // Disassemble third instruction
  core::Instruction inst3 = cpu_->Disassemble(code + 4, sizeof(code) - 4, 0x8004);
  EXPECT_EQ(inst3.mnemonic, "NOP");
  EXPECT_EQ(inst3.Size(), 1);

  // Disassemble fourth instruction
  core::Instruction inst4 = cpu_->Disassemble(code + 5, sizeof(code) - 5, 0x8005);
  EXPECT_EQ(inst4.mnemonic, "JMP");
  EXPECT_EQ(inst4.Size(), 3);
}

// Test 65C02 variant
TEST_F(Cpu6502Test, C02Variant) {
  auto cpu_c02 = std::make_unique<Cpu6502>(CpuVariant::WDC_65C02);
  EXPECT_EQ(cpu_c02->GetVariant(), CpuVariant::WDC_65C02);

  // STZ zero page (65C02 only)
  uint8_t code[] = {0x64, 0x10};  // STZ $10
  core::Instruction inst = cpu_c02->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "STZ");
  EXPECT_EQ(inst.operand, "$10");
  EXPECT_EQ(inst.mode, core::AddressingMode::ZERO_PAGE);
}

// Test BRA (65C02 only)
TEST_F(Cpu6502Test, C02BRA) {
  auto cpu_c02 = std::make_unique<Cpu6502>(CpuVariant::WDC_65C02);

  uint8_t code[] = {0x80, 0x0E};  // BRA +14
  core::Instruction inst = cpu_c02->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "BRA");
  EXPECT_TRUE(inst.is_branch);
  EXPECT_EQ(inst.target_address, 0x8010);
}

// Test all branch variants
TEST_F(Cpu6502Test, AllBranches) {
  struct BranchTest {
    uint8_t opcode;
    const char* mnemonic;
  };

  BranchTest branches[] = {
      {0x10, "BPL"},
      {0x30, "BMI"},
      {0x50, "BVC"},
      {0x70, "BVS"},
      {0x90, "BCC"},
      {0xB0, "BCS"},
      {0xD0, "BNE"},
      {0xF0, "BEQ"},
  };

  for (const auto& test : branches) {
    uint8_t code[] = {test.opcode, 0x00};
    core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);
    EXPECT_EQ(inst.mnemonic, test.mnemonic);
    EXPECT_TRUE(inst.is_branch);
  }
}

// Test instruction byte copying
TEST_F(Cpu6502Test, InstructionBytes) {
  uint8_t code[] = {0xAD, 0x34, 0x12};  // LDA $1234
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  ASSERT_EQ(inst.bytes.size(), 3);
  EXPECT_EQ(inst.bytes[0], 0xAD);
  EXPECT_EQ(inst.bytes[1], 0x34);
  EXPECT_EQ(inst.bytes[2], 0x12);
}

// Test address field
TEST_F(Cpu6502Test, InstructionAddress) {
  uint8_t code[] = {0xEA};  // NOP

  core::Instruction inst1 = cpu_->Disassemble(code, sizeof(code), 0x8000);
  EXPECT_EQ(inst1.address, 0x8000);

  core::Instruction inst2 = cpu_->Disassemble(code, sizeof(code), 0x0000);
  EXPECT_EQ(inst2.address, 0x0000);

  core::Instruction inst3 = cpu_->Disassemble(code, sizeof(code), 0xFFFF);
  EXPECT_EQ(inst3.address, 0xFFFF);
}

// Test factory functions
TEST_F(Cpu6502Test, FactoryFunctions) {
  auto cpu_6502 = Create6502Plugin();
  EXPECT_NE(cpu_6502, nullptr);
  EXPECT_EQ(cpu_6502->GetVariant(), CpuVariant::MOS_6502);

  auto cpu_65c02 = Create65C02Plugin();
  EXPECT_NE(cpu_65c02, nullptr);
  EXPECT_EQ(cpu_65c02->GetVariant(), CpuVariant::WDC_65C02);
}

// Test edge case: insufficient data
TEST_F(Cpu6502Test, InsufficientData) {
  uint8_t code[] = {0xAD};  // LDA absolute - needs 3 bytes but only 1
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  // Should still return something reasonable
  EXPECT_EQ(inst.mnemonic, "LDA");
  EXPECT_EQ(inst.address, 0x8000);
}

// Test little-endian byte order for addresses
TEST_F(Cpu6502Test, LittleEndianAddresses) {
  uint8_t code[] = {0x4C, 0x34, 0x12};  // JMP $1234
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.operand, "$1234");  // Not $3412
  EXPECT_EQ(inst.target_address, 0x1234);
}

// Test all arithmetic operations
TEST_F(Cpu6502Test, ArithmeticOps) {
  uint8_t adc[] = {0x69, 0x01};  // ADC #$01
  uint8_t sbc[] = {0xE9, 0x01};  // SBC #$01

  core::Instruction inst_adc = cpu_->Disassemble(adc, sizeof(adc), 0x8000);
  EXPECT_EQ(inst_adc.mnemonic, "ADC");

  core::Instruction inst_sbc = cpu_->Disassemble(sbc, sizeof(sbc), 0x8000);
  EXPECT_EQ(inst_sbc.mnemonic, "SBC");
}

// Test all logical operations
TEST_F(Cpu6502Test, LogicalOps) {
  uint8_t and_op[] = {0x29, 0xFF};  // AND #$FF
  uint8_t ora[] = {0x09, 0xFF};     // ORA #$FF
  uint8_t eor[] = {0x49, 0xFF};     // EOR #$FF

  EXPECT_EQ(cpu_->Disassemble(and_op, sizeof(and_op), 0x8000).mnemonic, "AND");
  EXPECT_EQ(cpu_->Disassemble(ora, sizeof(ora), 0x8000).mnemonic, "ORA");
  EXPECT_EQ(cpu_->Disassemble(eor, sizeof(eor), 0x8000).mnemonic, "EOR");
}

// Test stack operations
TEST_F(Cpu6502Test, StackOps) {
  uint8_t pha[] = {0x48};  // PHA
  uint8_t pla[] = {0x68};  // PLA
  uint8_t php[] = {0x08};  // PHP
  uint8_t plp[] = {0x28};  // PLP

  EXPECT_EQ(cpu_->Disassemble(pha, sizeof(pha), 0x8000).mnemonic, "PHA");
  EXPECT_EQ(cpu_->Disassemble(pla, sizeof(pla), 0x8000).mnemonic, "PLA");
  EXPECT_EQ(cpu_->Disassemble(php, sizeof(php), 0x8000).mnemonic, "PHP");
  EXPECT_EQ(cpu_->Disassemble(plp, sizeof(plp), 0x8000).mnemonic, "PLP");
}

}  // namespace
}  // namespace m6502
}  // namespace cpu
}  // namespace sourcerer
