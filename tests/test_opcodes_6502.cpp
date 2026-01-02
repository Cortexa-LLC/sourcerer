// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "cpu/m6502/opcodes_6502.h"

#include <gtest/gtest.h>

#include <set>

namespace sourcerer {
namespace cpu {
namespace m6502 {
namespace {

// Test fixture for opcode table tests
class OpcodeTableTest : public ::testing::Test {
 protected:
  void SetUp() override {}
};

// Test that all 256 opcodes have entries
TEST_F(OpcodeTableTest, AllOpcodesPresent) {
  for (int i = 0; i < 256; ++i) {
    const OpcodeInfo& info = OPCODE_TABLE_6502[i];
    EXPECT_EQ(info.opcode, i) << "Opcode mismatch at index " << i;
  }
}

// Test GetOpcodeInfo helper
TEST_F(OpcodeTableTest, GetOpcodeInfo) {
  const OpcodeInfo& info = GetOpcodeInfo(0xA9);  // LDA #
  EXPECT_EQ(info.opcode, 0xA9);
  EXPECT_STREQ(info.mnemonic, "LDA");
  EXPECT_EQ(info.mode, core::AddressingMode::IMMEDIATE);
  EXPECT_EQ(info.size, 2);
}

// Test common 6502 instructions
TEST_F(OpcodeTableTest, CommonInstructions) {
  // LDA immediate
  const OpcodeInfo& lda_imm = GetOpcodeInfo(0xA9);
  EXPECT_STREQ(lda_imm.mnemonic, "LDA");
  EXPECT_EQ(lda_imm.mode, core::AddressingMode::IMMEDIATE);
  EXPECT_EQ(lda_imm.size, 2);
  EXPECT_FALSE(lda_imm.is_illegal);

  // STA zero page
  const OpcodeInfo& sta_zp = GetOpcodeInfo(0x85);
  EXPECT_STREQ(sta_zp.mnemonic, "STA");
  EXPECT_EQ(sta_zp.mode, core::AddressingMode::ZERO_PAGE);
  EXPECT_EQ(sta_zp.size, 2);

  // JSR absolute
  const OpcodeInfo& jsr = GetOpcodeInfo(0x20);
  EXPECT_STREQ(jsr.mnemonic, "JSR");
  EXPECT_EQ(jsr.mode, core::AddressingMode::ABSOLUTE);
  EXPECT_EQ(jsr.size, 3);
  EXPECT_TRUE(jsr.is_call);
  EXPECT_FALSE(jsr.is_branch);
  EXPECT_FALSE(jsr.is_jump);

  // RTS implied
  const OpcodeInfo& rts = GetOpcodeInfo(0x60);
  EXPECT_STREQ(rts.mnemonic, "RTS");
  EXPECT_EQ(rts.mode, core::AddressingMode::IMPLIED);
  EXPECT_EQ(rts.size, 1);
  EXPECT_TRUE(rts.is_return);

  // NOP
  const OpcodeInfo& nop = GetOpcodeInfo(0xEA);
  EXPECT_STREQ(nop.mnemonic, "NOP");
  EXPECT_EQ(nop.mode, core::AddressingMode::IMPLIED);
  EXPECT_EQ(nop.size, 1);
}

// Test branch instructions
TEST_F(OpcodeTableTest, BranchInstructions) {
  // BNE
  const OpcodeInfo& bne = GetOpcodeInfo(0xD0);
  EXPECT_STREQ(bne.mnemonic, "BNE");
  EXPECT_EQ(bne.mode, core::AddressingMode::RELATIVE);
  EXPECT_EQ(bne.size, 2);
  EXPECT_TRUE(bne.is_branch);
  EXPECT_FALSE(bne.is_jump);

  // BEQ
  const OpcodeInfo& beq = GetOpcodeInfo(0xF0);
  EXPECT_STREQ(beq.mnemonic, "BEQ");
  EXPECT_TRUE(beq.is_branch);

  // BPL
  const OpcodeInfo& bpl = GetOpcodeInfo(0x10);
  EXPECT_STREQ(bpl.mnemonic, "BPL");
  EXPECT_TRUE(bpl.is_branch);

  // BMI
  const OpcodeInfo& bmi = GetOpcodeInfo(0x30);
  EXPECT_STREQ(bmi.mnemonic, "BMI");
  EXPECT_TRUE(bmi.is_branch);

  // BCC
  const OpcodeInfo& bcc = GetOpcodeInfo(0x90);
  EXPECT_STREQ(bcc.mnemonic, "BCC");
  EXPECT_TRUE(bcc.is_branch);

  // BCS
  const OpcodeInfo& bcs = GetOpcodeInfo(0xB0);
  EXPECT_STREQ(bcs.mnemonic, "BCS");
  EXPECT_TRUE(bcs.is_branch);

  // BVC
  const OpcodeInfo& bvc = GetOpcodeInfo(0x50);
  EXPECT_STREQ(bvc.mnemonic, "BVC");
  EXPECT_TRUE(bvc.is_branch);

  // BVS
  const OpcodeInfo& bvs = GetOpcodeInfo(0x70);
  EXPECT_STREQ(bvs.mnemonic, "BVS");
  EXPECT_TRUE(bvs.is_branch);
}

// Test jump instructions
TEST_F(OpcodeTableTest, JumpInstructions) {
  // JMP absolute
  const OpcodeInfo& jmp_abs = GetOpcodeInfo(0x4C);
  EXPECT_STREQ(jmp_abs.mnemonic, "JMP");
  EXPECT_EQ(jmp_abs.mode, core::AddressingMode::ABSOLUTE);
  EXPECT_EQ(jmp_abs.size, 3);
  EXPECT_TRUE(jmp_abs.is_jump);
  EXPECT_FALSE(jmp_abs.is_branch);
  EXPECT_FALSE(jmp_abs.is_call);

  // JMP indirect
  const OpcodeInfo& jmp_ind = GetOpcodeInfo(0x6C);
  EXPECT_STREQ(jmp_ind.mnemonic, "JMP");
  EXPECT_EQ(jmp_ind.mode, core::AddressingMode::INDIRECT);
  EXPECT_EQ(jmp_ind.size, 3);
  EXPECT_TRUE(jmp_ind.is_jump);
}

// Test return instructions
TEST_F(OpcodeTableTest, ReturnInstructions) {
  // RTS
  const OpcodeInfo& rts = GetOpcodeInfo(0x60);
  EXPECT_STREQ(rts.mnemonic, "RTS");
  EXPECT_TRUE(rts.is_return);

  // RTI
  const OpcodeInfo& rti = GetOpcodeInfo(0x40);
  EXPECT_STREQ(rti.mnemonic, "RTI");
  EXPECT_TRUE(rti.is_return);
}

// Test addressing modes
TEST_F(OpcodeTableTest, AddressingModes) {
  // Immediate
  EXPECT_EQ(GetOpcodeInfo(0xA9).mode, core::AddressingMode::IMMEDIATE);  // LDA #

  // Zero page
  EXPECT_EQ(GetOpcodeInfo(0xA5).mode, core::AddressingMode::ZERO_PAGE);  // LDA $ZP

  // Zero page X
  EXPECT_EQ(GetOpcodeInfo(0xB5).mode, core::AddressingMode::ZERO_PAGE_X);  // LDA $ZP,X

  // Zero page Y
  EXPECT_EQ(GetOpcodeInfo(0xB6).mode, core::AddressingMode::ZERO_PAGE_Y);  // LDX $ZP,Y

  // Absolute
  EXPECT_EQ(GetOpcodeInfo(0xAD).mode, core::AddressingMode::ABSOLUTE);  // LDA $ABS

  // Absolute X
  EXPECT_EQ(GetOpcodeInfo(0xBD).mode, core::AddressingMode::ABSOLUTE_X);  // LDA $ABS,X

  // Absolute Y
  EXPECT_EQ(GetOpcodeInfo(0xB9).mode, core::AddressingMode::ABSOLUTE_Y);  // LDA $ABS,Y

  // Indexed indirect
  EXPECT_EQ(GetOpcodeInfo(0xA1).mode, core::AddressingMode::INDEXED_INDIRECT);  // LDA ($ZP,X)

  // Indirect indexed
  EXPECT_EQ(GetOpcodeInfo(0xB1).mode, core::AddressingMode::INDIRECT_INDEXED);  // LDA ($ZP),Y

  // Implied
  EXPECT_EQ(GetOpcodeInfo(0xEA).mode, core::AddressingMode::IMPLIED);  // NOP

  // Accumulator
  EXPECT_EQ(GetOpcodeInfo(0x0A).mode, core::AddressingMode::ACCUMULATOR);  // ASL A

  // Relative (branches)
  EXPECT_EQ(GetOpcodeInfo(0xD0).mode, core::AddressingMode::RELATIVE);  // BNE
}

// Test instruction sizes
TEST_F(OpcodeTableTest, InstructionSizes) {
  // 1-byte instructions
  EXPECT_EQ(GetOpcodeInfo(0xEA).size, 1);  // NOP
  EXPECT_EQ(GetOpcodeInfo(0x60).size, 1);  // RTS
  EXPECT_EQ(GetOpcodeInfo(0x0A).size, 1);  // ASL A

  // 2-byte instructions
  EXPECT_EQ(GetOpcodeInfo(0xA9).size, 2);  // LDA #
  EXPECT_EQ(GetOpcodeInfo(0xA5).size, 2);  // LDA $ZP
  EXPECT_EQ(GetOpcodeInfo(0xD0).size, 2);  // BNE

  // 3-byte instructions
  EXPECT_EQ(GetOpcodeInfo(0xAD).size, 3);  // LDA $ABS
  EXPECT_EQ(GetOpcodeInfo(0x20).size, 3);  // JSR
  EXPECT_EQ(GetOpcodeInfo(0x4C).size, 3);  // JMP
}

// Test 65C02-specific instructions
TEST_F(OpcodeTableTest, C02Instructions) {
  // STZ zero page (0x64)
  const OpcodeInfo& stz_zp = GetOpcodeInfo(0x64);
  EXPECT_STREQ(stz_zp.mnemonic, "STZ");
  EXPECT_EQ(stz_zp.mode, core::AddressingMode::ZERO_PAGE);
  EXPECT_TRUE(stz_zp.is_65c02_only);

  // BRA (0x80)
  const OpcodeInfo& bra = GetOpcodeInfo(0x80);
  EXPECT_STREQ(bra.mnemonic, "BRA");
  EXPECT_EQ(bra.mode, core::AddressingMode::RELATIVE);
  EXPECT_TRUE(bra.is_branch);
  EXPECT_TRUE(bra.is_65c02_only);

  // PHX (0xDA)
  const OpcodeInfo& phx = GetOpcodeInfo(0xDA);
  EXPECT_STREQ(phx.mnemonic, "PHX");
  EXPECT_TRUE(phx.is_65c02_only);

  // PLX (0xFA)
  const OpcodeInfo& plx = GetOpcodeInfo(0xFA);
  EXPECT_STREQ(plx.mnemonic, "PLX");
  EXPECT_TRUE(plx.is_65c02_only);
}

// Test IsValidOpcode function
TEST_F(OpcodeTableTest, IsValidOpcode) {
  // Standard 6502 opcodes
  EXPECT_TRUE(IsValidOpcode(0xA9, false, false));  // LDA # - valid on all
  EXPECT_TRUE(IsValidOpcode(0x20, false, false));  // JSR - valid on all
  EXPECT_TRUE(IsValidOpcode(0xEA, false, false));  // NOP - valid on all

  // 65C02-only opcodes
  EXPECT_FALSE(IsValidOpcode(0x64, false, false));  // STZ - not valid on NMOS 6502
  EXPECT_TRUE(IsValidOpcode(0x64, true, false));    // STZ - valid on 65C02
  EXPECT_FALSE(IsValidOpcode(0x80, false, false));  // BRA - not valid on NMOS 6502
  EXPECT_TRUE(IsValidOpcode(0x80, true, false));    // BRA - valid on 65C02

  // Illegal opcodes (examples)
  const OpcodeInfo& info_02 = GetOpcodeInfo(0x02);
  if (info_02.is_illegal) {
    EXPECT_FALSE(IsValidOpcode(0x02, false, false));  // Not valid without illegal flag
    EXPECT_TRUE(IsValidOpcode(0x02, false, true));    // Valid with illegal flag
  }
}

// Test all LDA variants
TEST_F(OpcodeTableTest, LDAVariants) {
  EXPECT_STREQ(GetOpcodeInfo(0xA9).mnemonic, "LDA");  // LDA #
  EXPECT_STREQ(GetOpcodeInfo(0xA5).mnemonic, "LDA");  // LDA $ZP
  EXPECT_STREQ(GetOpcodeInfo(0xB5).mnemonic, "LDA");  // LDA $ZP,X
  EXPECT_STREQ(GetOpcodeInfo(0xAD).mnemonic, "LDA");  // LDA $ABS
  EXPECT_STREQ(GetOpcodeInfo(0xBD).mnemonic, "LDA");  // LDA $ABS,X
  EXPECT_STREQ(GetOpcodeInfo(0xB9).mnemonic, "LDA");  // LDA $ABS,Y
  EXPECT_STREQ(GetOpcodeInfo(0xA1).mnemonic, "LDA");  // LDA ($ZP,X)
  EXPECT_STREQ(GetOpcodeInfo(0xB1).mnemonic, "LDA");  // LDA ($ZP),Y
}

// Test all STA variants
TEST_F(OpcodeTableTest, STAVariants) {
  EXPECT_STREQ(GetOpcodeInfo(0x85).mnemonic, "STA");  // STA $ZP
  EXPECT_STREQ(GetOpcodeInfo(0x95).mnemonic, "STA");  // STA $ZP,X
  EXPECT_STREQ(GetOpcodeInfo(0x8D).mnemonic, "STA");  // STA $ABS
  EXPECT_STREQ(GetOpcodeInfo(0x9D).mnemonic, "STA");  // STA $ABS,X
  EXPECT_STREQ(GetOpcodeInfo(0x99).mnemonic, "STA");  // STA $ABS,Y
  EXPECT_STREQ(GetOpcodeInfo(0x81).mnemonic, "STA");  // STA ($ZP,X)
  EXPECT_STREQ(GetOpcodeInfo(0x91).mnemonic, "STA");  // STA ($ZP),Y
}

// Test arithmetic instructions
TEST_F(OpcodeTableTest, ArithmeticInstructions) {
  EXPECT_STREQ(GetOpcodeInfo(0x69).mnemonic, "ADC");  // ADC #
  EXPECT_STREQ(GetOpcodeInfo(0xE9).mnemonic, "SBC");  // SBC #
  EXPECT_STREQ(GetOpcodeInfo(0xC9).mnemonic, "CMP");  // CMP #
  EXPECT_STREQ(GetOpcodeInfo(0xE0).mnemonic, "CPX");  // CPX #
  EXPECT_STREQ(GetOpcodeInfo(0xC0).mnemonic, "CPY");  // CPY #
}

// Test logical instructions
TEST_F(OpcodeTableTest, LogicalInstructions) {
  EXPECT_STREQ(GetOpcodeInfo(0x29).mnemonic, "AND");  // AND #
  EXPECT_STREQ(GetOpcodeInfo(0x09).mnemonic, "ORA");  // ORA #
  EXPECT_STREQ(GetOpcodeInfo(0x49).mnemonic, "EOR");  // EOR #
  EXPECT_STREQ(GetOpcodeInfo(0x24).mnemonic, "BIT");  // BIT $ZP
}

// Test shift and rotate instructions
TEST_F(OpcodeTableTest, ShiftRotateInstructions) {
  EXPECT_STREQ(GetOpcodeInfo(0x0A).mnemonic, "ASL");  // ASL A
  EXPECT_STREQ(GetOpcodeInfo(0x4A).mnemonic, "LSR");  // LSR A
  EXPECT_STREQ(GetOpcodeInfo(0x2A).mnemonic, "ROL");  // ROL A
  EXPECT_STREQ(GetOpcodeInfo(0x6A).mnemonic, "ROR");  // ROR A
}

// Test increment/decrement instructions
TEST_F(OpcodeTableTest, IncDecInstructions) {
  EXPECT_STREQ(GetOpcodeInfo(0xE6).mnemonic, "INC");  // INC $ZP
  EXPECT_STREQ(GetOpcodeInfo(0xC6).mnemonic, "DEC");  // DEC $ZP
  EXPECT_STREQ(GetOpcodeInfo(0xE8).mnemonic, "INX");  // INX
  EXPECT_STREQ(GetOpcodeInfo(0xCA).mnemonic, "DEX");  // DEX
  EXPECT_STREQ(GetOpcodeInfo(0xC8).mnemonic, "INY");  // INY
  EXPECT_STREQ(GetOpcodeInfo(0x88).mnemonic, "DEY");  // DEY
}

// Test transfer instructions
TEST_F(OpcodeTableTest, TransferInstructions) {
  EXPECT_STREQ(GetOpcodeInfo(0xAA).mnemonic, "TAX");  // TAX
  EXPECT_STREQ(GetOpcodeInfo(0x8A).mnemonic, "TXA");  // TXA
  EXPECT_STREQ(GetOpcodeInfo(0xA8).mnemonic, "TAY");  // TAY
  EXPECT_STREQ(GetOpcodeInfo(0x98).mnemonic, "TYA");  // TYA
  EXPECT_STREQ(GetOpcodeInfo(0xBA).mnemonic, "TSX");  // TSX
  EXPECT_STREQ(GetOpcodeInfo(0x9A).mnemonic, "TXS");  // TXS
}

// Test stack instructions
TEST_F(OpcodeTableTest, StackInstructions) {
  EXPECT_STREQ(GetOpcodeInfo(0x48).mnemonic, "PHA");  // PHA
  EXPECT_STREQ(GetOpcodeInfo(0x68).mnemonic, "PLA");  // PLA
  EXPECT_STREQ(GetOpcodeInfo(0x08).mnemonic, "PHP");  // PHP
  EXPECT_STREQ(GetOpcodeInfo(0x28).mnemonic, "PLP");  // PLP
}

// Test flag instructions
TEST_F(OpcodeTableTest, FlagInstructions) {
  EXPECT_STREQ(GetOpcodeInfo(0x18).mnemonic, "CLC");  // CLC
  EXPECT_STREQ(GetOpcodeInfo(0x38).mnemonic, "SEC");  // SEC
  EXPECT_STREQ(GetOpcodeInfo(0x58).mnemonic, "CLI");  // CLI
  EXPECT_STREQ(GetOpcodeInfo(0x78).mnemonic, "SEI");  // SEI
  EXPECT_STREQ(GetOpcodeInfo(0xB8).mnemonic, "CLV");  // CLV
  EXPECT_STREQ(GetOpcodeInfo(0xD8).mnemonic, "CLD");  // CLD
  EXPECT_STREQ(GetOpcodeInfo(0xF8).mnemonic, "SED");  // SED
}

// Test special instructions
TEST_F(OpcodeTableTest, SpecialInstructions) {
  EXPECT_STREQ(GetOpcodeInfo(0x00).mnemonic, "BRK");  // BRK
  EXPECT_STREQ(GetOpcodeInfo(0xEA).mnemonic, "NOP");  // NOP
}

// Test that cycle counts are reasonable
TEST_F(OpcodeTableTest, CycleCounts) {
  // 1-byte implied instructions are typically 2 cycles
  EXPECT_GE(GetOpcodeInfo(0xEA).cycles, 2);  // NOP

  // Branches are 2+ cycles
  EXPECT_GE(GetOpcodeInfo(0xD0).cycles, 2);  // BNE

  // Absolute addressing is typically 3-4 cycles
  EXPECT_GE(GetOpcodeInfo(0xAD).cycles, 3);  // LDA $ABS

  // JSR is 6 cycles
  EXPECT_EQ(GetOpcodeInfo(0x20).cycles, 6);  // JSR

  // RTS is 6 cycles
  EXPECT_EQ(GetOpcodeInfo(0x60).cycles, 6);  // RTS
}

}  // namespace
}  // namespace m6502
}  // namespace cpu
}  // namespace sourcerer
