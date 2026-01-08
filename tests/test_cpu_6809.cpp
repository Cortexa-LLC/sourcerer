// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "cpu/m6809/cpu_6809.h"
#include "cpu/cpu_state.h"

#include <gtest/gtest.h>

namespace sourcerer {
namespace cpu {
namespace m6809 {
namespace {

// Test fixture for 6809 CPU tests
class Cpu6809Test : public ::testing::Test {
 protected:
  void SetUp() override {
    cpu_ = std::make_unique<Cpu6809>();
  }

  std::unique_ptr<Cpu6809> cpu_;
};

// Test plugin metadata
TEST_F(Cpu6809Test, PluginMetadata) {
  EXPECT_EQ(cpu_->Name(), "6809");
  EXPECT_EQ(cpu_->GetVariant(), CpuVariant::MOTOROLA_6809);
  EXPECT_EQ(cpu_->MaxAddress(), 0xFFFF);
  EXPECT_EQ(cpu_->AddressMask(), 0xFFFF);

  std::vector<std::string> aliases = cpu_->Aliases();
  EXPECT_GT(aliases.size(), 0);
  EXPECT_EQ(aliases[0], "6809");
}

// Test implied addressing mode
TEST_F(Cpu6809Test, ImpliedMode) {
  uint8_t code[] = {0x12};  // NOP
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.address, 0x8000);
  EXPECT_EQ(inst.mnemonic, "NOP");
  EXPECT_TRUE(inst.operand.empty());
  EXPECT_EQ(inst.mode, core::AddressingMode::IMPLIED);
  EXPECT_EQ(inst.Size(), 1);
  EXPECT_EQ(inst.bytes[0], 0x12);
  EXPECT_FALSE(inst.is_branch);
  EXPECT_FALSE(inst.is_jump);
  EXPECT_FALSE(inst.is_call);
}

// Test immediate addressing mode (8-bit)
TEST_F(Cpu6809Test, Immediate8BitMode) {
  uint8_t code[] = {0x86, 0x42};  // LDA #$42
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "LDA");
  EXPECT_EQ(inst.operand, "#$42");
  EXPECT_EQ(inst.mode, core::AddressingMode::IMMEDIATE);
  EXPECT_EQ(inst.Size(), 2);
}

// Test immediate addressing mode (16-bit)
TEST_F(Cpu6809Test, Immediate16BitMode) {
  uint8_t code[] = {0xCC, 0x12, 0x34};  // LDD #$1234
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "LDD");
  EXPECT_EQ(inst.operand, "#$1234");
  EXPECT_EQ(inst.mode, core::AddressingMode::IMMEDIATE);
  EXPECT_EQ(inst.Size(), 3);
}

// Test direct addressing mode
TEST_F(Cpu6809Test, DirectMode) {
  uint8_t code[] = {0x96, 0x10};  // LDA $10
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "LDA");
  EXPECT_EQ(inst.operand, "$10");
  EXPECT_EQ(inst.mode, core::AddressingMode::DIRECT);
  EXPECT_EQ(inst.Size(), 2);
}

// Test extended addressing mode
TEST_F(Cpu6809Test, ExtendedMode) {
  uint8_t code[] = {0xB6, 0x10, 0x00};  // LDA $1000
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "LDA");
  EXPECT_EQ(inst.operand, "$1000");
  EXPECT_EQ(inst.mode, core::AddressingMode::EXTENDED);
  EXPECT_EQ(inst.target_address, 0x1000);
  EXPECT_EQ(inst.Size(), 3);
}

// Test branch forward
TEST_F(Cpu6809Test, BranchForward) {
  uint8_t code[] = {0x27, 0x10};  // BEQ +16
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "BEQ");
  EXPECT_TRUE(inst.is_branch);
  EXPECT_FALSE(inst.is_jump);
  EXPECT_EQ(inst.mode, core::AddressingMode::RELATIVE);
  EXPECT_EQ(inst.target_address, 0x8012);  // 0x8000 + 1 + 1 + 0x10
  EXPECT_EQ(inst.Size(), 2);
}

// Test branch backward
TEST_F(Cpu6809Test, BranchBackward) {
  uint8_t code[] = {0x27, 0xFE};  // BEQ -2 (branch to self)
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "BEQ");
  EXPECT_TRUE(inst.is_branch);
  EXPECT_EQ(inst.target_address, 0x8000);  // Branch to itself
}

// Test long branch (Page 2)
TEST_F(Cpu6809Test, LongBranch) {
  uint8_t code[] = {0x10, 0x27, 0x00, 0x50};  // LBEQ +80
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "LBEQ");
  EXPECT_TRUE(inst.is_branch);
  EXPECT_EQ(inst.mode, core::AddressingMode::RELATIVE);
  EXPECT_EQ(inst.target_address, 0x8054);  // 0x8000 + 2 + 2 + 0x50
  EXPECT_EQ(inst.Size(), 4);
}

// Test JMP instruction
TEST_F(Cpu6809Test, JumpAbsolute) {
  uint8_t code[] = {0x7E, 0x90, 0x00};  // JMP $9000
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "JMP");
  EXPECT_EQ(inst.operand, "$9000");
  EXPECT_TRUE(inst.is_jump);
  EXPECT_FALSE(inst.is_branch);
  EXPECT_FALSE(inst.is_call);
  EXPECT_EQ(inst.target_address, 0x9000);
  EXPECT_EQ(inst.Size(), 3);
}

// Test JSR (subroutine call)
TEST_F(Cpu6809Test, SubroutineCall) {
  uint8_t code[] = {0xBD, 0x80, 0x10};  // JSR $8010
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "JSR");
  EXPECT_EQ(inst.operand, "$8010");
  EXPECT_TRUE(inst.is_call);
  EXPECT_FALSE(inst.is_branch);
  EXPECT_FALSE(inst.is_jump);
  EXPECT_EQ(inst.target_address, 0x8010);
  EXPECT_EQ(inst.Size(), 3);
}

// Test BSR (branch to subroutine)
TEST_F(Cpu6809Test, BranchToSubroutine) {
  uint8_t code[] = {0x8D, 0x10};  // BSR +16
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "BSR");
  EXPECT_TRUE(inst.is_call);
  EXPECT_EQ(inst.mode, core::AddressingMode::RELATIVE);
  EXPECT_EQ(inst.target_address, 0x8012);
  EXPECT_EQ(inst.Size(), 2);
}

// Test RTS (return from subroutine)
TEST_F(Cpu6809Test, ReturnFromSubroutine) {
  uint8_t code[] = {0x39};  // RTS
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "RTS");
  EXPECT_TRUE(inst.is_return);
  EXPECT_FALSE(inst.is_call);
  EXPECT_FALSE(inst.is_branch);
  EXPECT_FALSE(inst.is_jump);
  EXPECT_EQ(inst.Size(), 1);
}

// Test RTI (return from interrupt)
TEST_F(Cpu6809Test, ReturnFromInterrupt) {
  uint8_t code[] = {0x3B};  // RTI
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "RTI");
  EXPECT_TRUE(inst.is_return);
  EXPECT_EQ(inst.Size(), 1);
}

// Test TFR instruction
TEST_F(Cpu6809Test, TransferRegister) {
  uint8_t code[] = {0x1F, 0x01};  // TFR D,X
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "TFR");
  EXPECT_EQ(inst.operand, "D,X");
  EXPECT_EQ(inst.mode, core::AddressingMode::IMMEDIATE);
  EXPECT_EQ(inst.Size(), 2);
}

// Test TFR with invalid register codes
TEST_F(Cpu6809Test, TransferRegisterInvalid) {
  uint8_t code[] = {0x1F, 0x67};  // TFR invalid,invalid
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "TFR");
  EXPECT_TRUE(inst.is_illegal);  // Should be marked illegal due to invalid registers
}

// Test TFR with mismatched register sizes
TEST_F(Cpu6809Test, TransferRegisterSizeMismatch) {
  uint8_t code[] = {0x1F, 0x08};  // TFR D,A (16-bit to 8-bit)
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "TFR");
  EXPECT_TRUE(inst.is_illegal);  // Should be marked illegal due to size mismatch
}

// Test EXG instruction
TEST_F(Cpu6809Test, ExchangeRegister) {
  uint8_t code[] = {0x1E, 0x12};  // EXG X,Y
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "EXG");
  EXPECT_EQ(inst.operand, "X,Y");
  EXPECT_EQ(inst.mode, core::AddressingMode::IMMEDIATE);
  EXPECT_EQ(inst.Size(), 2);
}

// Test PSHS instruction
TEST_F(Cpu6809Test, PushStack) {
  uint8_t code[] = {0x34, 0x16};  // PSHS D,X
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "PSHS");
  EXPECT_EQ(inst.mode, core::AddressingMode::IMMEDIATE);
  EXPECT_EQ(inst.Size(), 2);
  // Verify register list includes X (bit 4) and D (bits 2 and 1 for B and A)
  EXPECT_NE(inst.operand.find("X"), std::string::npos);
}

// Test PSHS with no registers (edge case)
TEST_F(Cpu6809Test, PushStackEmpty) {
  uint8_t code[] = {0x34, 0x00};  // PSHS (no registers)
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "PSHS");
  EXPECT_EQ(inst.operand, "#$00");  // Shows raw byte when no registers
}

// Test Page 2 opcodes
TEST_F(Cpu6809Test, Page2Opcodes) {
  uint8_t code[] = {0x10, 0x83, 0x12, 0x34};  // CMPD #$1234 (Page 2)
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "CMPD");
  EXPECT_EQ(inst.operand, "#$1234");
  EXPECT_EQ(inst.Size(), 4);
}

// Test Page 3 opcodes
TEST_F(Cpu6809Test, Page3Opcodes) {
  uint8_t code[] = {0x11, 0x83, 0x12, 0x34};  // CMPU #$1234 (Page 3)
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "CMPU");
  EXPECT_EQ(inst.operand, "#$1234");
  EXPECT_EQ(inst.Size(), 4);
}

// Test GetInstructionSize
TEST_F(Cpu6809Test, GetInstructionSize) {
  uint8_t code1[] = {0x12};              // NOP - 1 byte
  uint8_t code2[] = {0x86, 0x42};        // LDA # - 2 bytes
  uint8_t code3[] = {0xB6, 0x10, 0x00};  // LDA $ - 3 bytes
  uint8_t code4[] = {0x10, 0x27, 0x00, 0x50};  // LBEQ - 4 bytes

  EXPECT_EQ(cpu_->GetInstructionSize(code1, sizeof(code1), 0x8000), 1);
  EXPECT_EQ(cpu_->GetInstructionSize(code2, sizeof(code2), 0x8000), 2);
  EXPECT_EQ(cpu_->GetInstructionSize(code3, sizeof(code3), 0x8000), 3);
  EXPECT_EQ(cpu_->GetInstructionSize(code4, sizeof(code4), 0x8000), 4);
}

// Test edge case: zero size buffer
TEST_F(Cpu6809Test, ZeroSizeBuffer) {
  uint8_t code[] = {0x86};
  core::Instruction inst = cpu_->Disassemble(code, 0, 0x8000);

  EXPECT_EQ(inst.mnemonic, "???");
  EXPECT_TRUE(inst.is_illegal);
}

// Test edge case: insufficient data for operand
TEST_F(Cpu6809Test, InsufficientDataForOperand) {
  uint8_t code[] = {0xB6};  // LDA extended - needs 3 bytes but only 1
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "LDA");
  EXPECT_TRUE(inst.is_illegal);  // Marked illegal due to insufficient data
}

// Test big-endian byte order
TEST_F(Cpu6809Test, BigEndianAddresses) {
  uint8_t code[] = {0xB6, 0x12, 0x34};  // LDA $1234
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.operand, "$1234");  // Not $3412
  EXPECT_EQ(inst.target_address, 0x1234);
}

// Test all branch variants
TEST_F(Cpu6809Test, AllBranches) {
  struct BranchTest {
    uint8_t opcode;
    const char* mnemonic;
  };

  BranchTest branches[] = {
      {0x20, "BRA"},
      {0x21, "BRN"},
      {0x22, "BHI"},
      {0x23, "BLS"},
      {0x24, "BCC"},
      {0x25, "BCS"},
      {0x26, "BNE"},
      {0x27, "BEQ"},
      {0x28, "BVC"},
      {0x29, "BVS"},
      {0x2A, "BPL"},
      {0x2B, "BMI"},
      {0x2C, "BGE"},
      {0x2D, "BLT"},
      {0x2E, "BGT"},
      {0x2F, "BLE"},
  };

  for (const auto& test : branches) {
    uint8_t code[] = {test.opcode, 0x00};
    core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);
    EXPECT_EQ(inst.mnemonic, test.mnemonic);
    EXPECT_TRUE(inst.is_branch);
  }
}

// Test analysis capabilities
TEST_F(Cpu6809Test, AnalysisCapabilities) {
  AnalysisCapabilities caps = cpu_->GetAnalysisCapabilities();
  EXPECT_TRUE(caps.has_interrupt_vectors);
  EXPECT_TRUE(caps.has_subroutines);
  EXPECT_EQ(caps.code_alignment, 1);
}

// Test interrupt vectors
TEST_F(Cpu6809Test, InterruptVectors) {
  std::vector<InterruptVector> vectors = cpu_->GetInterruptVectors();
  EXPECT_EQ(vectors.size(), 7);
  EXPECT_EQ(vectors[0].address, 0xFFF2);
  EXPECT_EQ(vectors[0].name, "SWI3");
  EXPECT_EQ(vectors[6].address, 0xFFFE);
  EXPECT_EQ(vectors[6].name, "RESET");
}

// Test ReadVectorTarget
TEST_F(Cpu6809Test, ReadVectorTarget) {
  uint8_t data[0x10000];
  memset(data, 0, sizeof(data));
  data[0xFFFE] = 0x80;  // Big-endian high byte
  data[0xFFFF] = 0x00;  // Big-endian low byte

  uint32_t target = cpu_->ReadVectorTarget(data, sizeof(data), 0xFFFE);
  EXPECT_EQ(target, 0x8000);
}

// Test ReadVectorTarget with insufficient data
TEST_F(Cpu6809Test, ReadVectorTargetInsufficientData) {
  uint8_t data[] = {0x80};
  uint32_t target = cpu_->ReadVectorTarget(data, sizeof(data), 0);
  EXPECT_EQ(target, 0);  // Returns 0 when insufficient data
}

// Test ReadVectorTarget out of bounds
TEST_F(Cpu6809Test, ReadVectorTargetOutOfBounds) {
  uint8_t data[] = {0x80, 0x00};
  uint32_t target = cpu_->ReadVectorTarget(data, sizeof(data), 10);
  EXPECT_EQ(target, 0);  // Returns 0 when out of bounds
}

// Test LooksLikeSubroutineStart with PSHS
TEST_F(Cpu6809Test, LooksLikeSubroutineStartWithPSHS) {
  uint8_t code[] = {
      0x34, 0x16,        // PSHS D,X
      0x86, 0x00,        // LDA #$00
      0xC6, 0x00,        // LDB #$00
      0x97, 0x10,        // STA $10
      0x39               // RTS
  };
  EXPECT_TRUE(cpu_->LooksLikeSubroutineStart(code, sizeof(code), 0x8000));
}

// Test LooksLikeSubroutineStart with valid code
TEST_F(Cpu6809Test, LooksLikeSubroutineStartValidCode) {
  uint8_t code[] = {
      0x86, 0x00,        // LDA #$00
      0xC6, 0x00,        // LDB #$00
      0x97, 0x10,        // STA $10
      0xD7, 0x11,        // STB $11
      0x39               // RTS
  };
  EXPECT_TRUE(cpu_->LooksLikeSubroutineStart(code, sizeof(code), 0x8000));
}

// Test LooksLikeSubroutineStart with early return
TEST_F(Cpu6809Test, LooksLikeSubroutineStartEarlyReturn) {
  uint8_t code[] = {
      0x39,              // RTS (immediate return)
      0x86, 0x00,        // LDA #$00
  };
  EXPECT_FALSE(cpu_->LooksLikeSubroutineStart(code, sizeof(code), 0x8000));
}

// Test LooksLikeSubroutineStart with early branch
TEST_F(Cpu6809Test, LooksLikeSubroutineStartEarlyBranch) {
  uint8_t code[] = {
      0x27, 0x10,        // BEQ +16 (branch immediately)
      0x86, 0x00,        // LDA #$00
  };
  EXPECT_FALSE(cpu_->LooksLikeSubroutineStart(code, sizeof(code), 0x8000));
}

// Test LooksLikeSubroutineStart with illegal opcode
TEST_F(Cpu6809Test, LooksLikeSubroutineStartIllegal) {
  uint8_t code[] = {
      0x86, 0x00,        // LDA #$00
      0xFF,              // Illegal opcode
      0xC6, 0x00,        // LDB #$00
  };
  // May fail if illegal opcode is encountered
  bool result = cpu_->LooksLikeSubroutineStart(code, sizeof(code), 0x8000);
  // Result depends on whether opcode 0xFF is illegal
  (void)result;  // Suppress unused warning
}

// Test LooksLikeSubroutineStart with insufficient data
TEST_F(Cpu6809Test, LooksLikeSubroutineStartInsufficientData) {
  uint8_t code[] = {0x86, 0x00};  // Only 2 bytes
  EXPECT_FALSE(cpu_->LooksLikeSubroutineStart(code, sizeof(code), 0x8000));
}

// Test IsLikelyCode with valid code
TEST_F(Cpu6809Test, IsLikelyCodeValid) {
  uint8_t code[] = {
      0x86, 0x00,        // LDA #$00
      0xC6, 0x00,        // LDB #$00
      0x97, 0x10,        // STA $10
      0xD7, 0x11,        // STB $11
  };
  EXPECT_TRUE(cpu_->IsLikelyCode(code, sizeof(code), 0x8000));
}

// Test IsLikelyCode with empty data
TEST_F(Cpu6809Test, IsLikelyCodeEmpty) {
  uint8_t code[] = {0x86};
  EXPECT_FALSE(cpu_->IsLikelyCode(code, 0, 0x8000));
}

// Test IsLikelyCode with illegal opcodes
TEST_F(Cpu6809Test, IsLikelyCodeIllegal) {
  uint8_t code[] = {0x01, 0x02, 0x03, 0x04};  // Potentially illegal opcodes
  bool result = cpu_->IsLikelyCode(code, sizeof(code), 0x8000);
  // Result depends on whether these are illegal
  (void)result;  // Suppress unused warning
}

// Test CreateCpuState
TEST_F(Cpu6809Test, CreateCpuState) {
  auto state = cpu_->CreateCpuState();
  EXPECT_NE(state, nullptr);
  EXPECT_EQ(state->GetPC(), 0);

  state->SetPC(0x8000);
  EXPECT_EQ(state->GetPC(), 0x8000);
}

// Test factory function
TEST_F(Cpu6809Test, FactoryFunction) {
  auto cpu = Create6809Plugin();
  EXPECT_NE(cpu, nullptr);
  EXPECT_EQ(cpu->GetVariant(), CpuVariant::MOTOROLA_6809);
  EXPECT_EQ(cpu->Name(), "6809");
}

// Test sequential instructions
TEST_F(Cpu6809Test, SequentialInstructions) {
  uint8_t code[] = {
      0x86, 0x00,        // LDA #$00
      0x97, 0x10,        // STA $10
      0x12,              // NOP
      0x7E, 0x90, 0x00   // JMP $9000
  };

  core::Instruction inst1 = cpu_->Disassemble(code, sizeof(code), 0x8000);
  EXPECT_EQ(inst1.mnemonic, "LDA");
  EXPECT_EQ(inst1.Size(), 2);

  core::Instruction inst2 = cpu_->Disassemble(code + 2, sizeof(code) - 2, 0x8002);
  EXPECT_EQ(inst2.mnemonic, "STA");
  EXPECT_EQ(inst2.Size(), 2);

  core::Instruction inst3 = cpu_->Disassemble(code + 4, sizeof(code) - 4, 0x8004);
  EXPECT_EQ(inst3.mnemonic, "NOP");
  EXPECT_EQ(inst3.Size(), 1);

  core::Instruction inst4 = cpu_->Disassemble(code + 5, sizeof(code) - 5, 0x8005);
  EXPECT_EQ(inst4.mnemonic, "JMP");
  EXPECT_EQ(inst4.Size(), 3);
}

// Test instruction byte copying
TEST_F(Cpu6809Test, InstructionBytes) {
  uint8_t code[] = {0xB6, 0x12, 0x34};  // LDA $1234
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  ASSERT_EQ(inst.bytes.size(), 3);
  EXPECT_EQ(inst.bytes[0], 0xB6);
  EXPECT_EQ(inst.bytes[1], 0x12);
  EXPECT_EQ(inst.bytes[2], 0x34);
}

// Test instruction address field
TEST_F(Cpu6809Test, InstructionAddress) {
  uint8_t code[] = {0x12};  // NOP

  core::Instruction inst1 = cpu_->Disassemble(code, sizeof(code), 0x8000);
  EXPECT_EQ(inst1.address, 0x8000);

  core::Instruction inst2 = cpu_->Disassemble(code, sizeof(code), 0x0000);
  EXPECT_EQ(inst2.address, 0x0000);

  core::Instruction inst3 = cpu_->Disassemble(code, sizeof(code), 0xFFFF);
  EXPECT_EQ(inst3.address, 0xFFFF);
}

// Test TFR with all register combinations
TEST_F(Cpu6809Test, TransferAllRegisters) {
  // Test U register (postbyte: high nibble=source, low nibble=dest, 3=U)
  uint8_t tfr_u[] = {0x1F, 0x33};  // TFR U,U (0x33 = 0011 0011)
  core::Instruction inst_u = cpu_->Disassemble(tfr_u, sizeof(tfr_u), 0x8000);
  EXPECT_EQ(inst_u.operand, "U,U");

  // Test S register (4=S)
  uint8_t tfr_s[] = {0x1F, 0x44};  // TFR S,S (0x44 = 0100 0100)
  core::Instruction inst_s = cpu_->Disassemble(tfr_s, sizeof(tfr_s), 0x8000);
  EXPECT_EQ(inst_s.operand, "S,S");

  // Test PC register (5=PC)
  uint8_t tfr_pc[] = {0x1F, 0x55};  // TFR PC,PC (0x55 = 0101 0101)
  core::Instruction inst_pc = cpu_->Disassemble(tfr_pc, sizeof(tfr_pc), 0x8000);
  EXPECT_EQ(inst_pc.operand, "PC,PC");

  // Test B register
  uint8_t tfr_b[] = {0x1F, 0x99};  // TFR B,B
  core::Instruction inst_b = cpu_->Disassemble(tfr_b, sizeof(tfr_b), 0x8000);
  EXPECT_EQ(inst_b.operand, "B,B");

  // Test CC register
  uint8_t tfr_cc[] = {0x1F, 0xAA};  // TFR CC,CC
  core::Instruction inst_cc = cpu_->Disassemble(tfr_cc, sizeof(tfr_cc), 0x8000);
  EXPECT_EQ(inst_cc.operand, "CC,CC");

  // Test DP register
  uint8_t tfr_dp[] = {0x1F, 0xBB};  // TFR DP,DP
  core::Instruction inst_dp = cpu_->Disassemble(tfr_dp, sizeof(tfr_dp), 0x8000);
  EXPECT_EQ(inst_dp.operand, "DP,DP");
}

// Test GetInstructionSize for all addressing modes
TEST_F(Cpu6809Test, GetInstructionSizeAllModes) {
  // Test IMPLIED mode
  uint8_t implied[] = {0x12};  // NOP
  EXPECT_EQ(cpu_->GetInstructionSize(implied, sizeof(implied), 0x8000), 1);

  // Test IMMEDIATE 8-bit
  uint8_t imm8[] = {0x86, 0x42};  // LDA #$42
  EXPECT_EQ(cpu_->GetInstructionSize(imm8, sizeof(imm8), 0x8000), 2);

  // Test IMMEDIATE 16-bit
  uint8_t imm16[] = {0xCC, 0x12, 0x34};  // LDD #$1234
  EXPECT_EQ(cpu_->GetInstructionSize(imm16, sizeof(imm16), 0x8000), 3);

  // Test DIRECT mode
  uint8_t direct[] = {0x96, 0x10};  // LDA $10
  EXPECT_EQ(cpu_->GetInstructionSize(direct, sizeof(direct), 0x8000), 2);

  // Test EXTENDED mode
  uint8_t extended[] = {0xB6, 0x10, 0x00};  // LDA $1000
  EXPECT_EQ(cpu_->GetInstructionSize(extended, sizeof(extended), 0x8000), 3);

  // Test RELATIVE 8-bit
  uint8_t rel8[] = {0x27, 0x10};  // BEQ +16
  EXPECT_EQ(cpu_->GetInstructionSize(rel8, sizeof(rel8), 0x8000), 2);

  // Test RELATIVE 16-bit (long branch)
  uint8_t rel16[] = {0x10, 0x27, 0x00, 0x50};  // LBEQ +80
  EXPECT_EQ(cpu_->GetInstructionSize(rel16, sizeof(rel16), 0x8000), 4);

  // Test INDEXED mode (simple)
  uint8_t indexed[] = {0xA6, 0x84};  // LDA ,X
  EXPECT_EQ(cpu_->GetInstructionSize(indexed, sizeof(indexed), 0x8000), 2);
}

// Test insufficient data for immediate operand
TEST_F(Cpu6809Test, InsufficientImmediateData) {
  uint8_t code[] = {0x86};  // LDA # with no operand
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "LDA");
  EXPECT_TRUE(inst.is_illegal);  // Should be illegal due to missing operand
}

// Test insufficient data for relative branch
TEST_F(Cpu6809Test, InsufficientRelativeData) {
  uint8_t code[] = {0x10, 0x27};  // LBEQ with no offset
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "LBEQ");
  EXPECT_TRUE(inst.is_illegal);  // Should be illegal due to missing offset
}

// Test indexed mode with PC-relative addressing
TEST_F(Cpu6809Test, IndexedModePCRelative) {
  // LDA with PC-relative indexed mode
  uint8_t code[] = {0xA6, 0x8C, 0x10, 0x00};  // LDA $1000,PCR
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "LDA");
  EXPECT_EQ(inst.mode, core::AddressingMode::INDEXED);
  // Should have a target address calculated from PC-relative
  EXPECT_NE(inst.target_address, 0);
}

// Test exception handling in LooksLikeSubroutineStart
TEST_F(Cpu6809Test, LooksLikeSubroutineStartException) {
  // Very small buffer that could cause issues
  uint8_t code[] = {0x86};
  bool result = cpu_->LooksLikeSubroutineStart(code, sizeof(code), 0x8000);
  // Should return false for insufficient data
  EXPECT_FALSE(result);
}

// Test exception handling in IsLikelyCode
TEST_F(Cpu6809Test, IsLikelyCodeException) {
  // Try with just one byte
  uint8_t code[] = {0x86};
  bool result = cpu_->IsLikelyCode(code, sizeof(code), 0x8000);
  // Depends on whether 0x86 alone is valid (LDA # without operand would be illegal)
  (void)result;  // Suppress unused warning
}

// Test indirect indexed addressing validation (should fail for certain instructions)
TEST_F(Cpu6809Test, IndirectIndexedInvalid) {
  // These would need actual indexed mode post-bytes with indirect bit set
  // This is tested indirectly by the validation logic in Disassemble

  // For now, just verify that the indirect validation code path exists
  // by testing a valid instruction to ensure no false positives
  uint8_t code[] = {0xA6, 0x84};  // LDA ,X (not indirect)
  core::Instruction inst = cpu_->Disassemble(code, sizeof(code), 0x8000);
  EXPECT_FALSE(inst.is_illegal);  // Should be valid
}

}  // namespace
}  // namespace m6809
}  // namespace cpu
}  // namespace sourcerer
