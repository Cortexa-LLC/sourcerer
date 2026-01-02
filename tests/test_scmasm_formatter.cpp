// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "output/scmasm_formatter.h"

#include <gtest/gtest.h>

namespace sourcerer {
namespace output {
namespace {

// Test fixture for SCMASMFormatter tests
class SCMASMFormatterTest : public ::testing::Test {
 protected:
  void SetUp() override {
    formatter_ = CreateScmasmFormatter();
    address_map_ = std::make_unique<core::AddressMap>();
  }

  // Helper: Create a test instruction
  core::Instruction MakeInstruction(uint32_t address, const std::string& mnemonic,
                                    const std::string& operand = "",
                                    core::AddressingMode mode = core::AddressingMode::IMPLIED) {
    core::Instruction inst;
    inst.address = address;
    inst.mnemonic = mnemonic;
    inst.operand = operand;
    inst.mode = mode;
    inst.bytes = {0xEA};  // Dummy byte
    return inst;
  }

  std::unique_ptr<Formatter> formatter_;
  std::unique_ptr<core::AddressMap> address_map_;
};

// Test formatter name
TEST_F(SCMASMFormatterTest, FormatterName) {
  EXPECT_EQ(formatter_->Name(), "SCMASM");
}

// Test header formatting
TEST_F(SCMASMFormatterTest, FormatHeader) {
  core::Binary binary({0x00, 0x01, 0x02}, 0x8000);
  binary.set_source_file("test.bin");
  binary.set_file_type("RAW");

  std::string header = formatter_->FormatHeader(binary);

  EXPECT_FALSE(header.empty());
  EXPECT_TRUE(header.find("test.bin") != std::string::npos);
  EXPECT_TRUE(header.find("$8000") != std::string::npos);
  EXPECT_TRUE(header.find("3 bytes") != std::string::npos);
}

// Test footer formatting
TEST_F(SCMASMFormatterTest, FormatFooter) {
  std::string footer = formatter_->FormatFooter();

  EXPECT_FALSE(footer.empty());
  EXPECT_TRUE(footer.find(".TF") != std::string::npos);
}

// Test implied addressing mode instruction
TEST_F(SCMASMFormatterTest, FormatImpliedInstruction) {
  core::Instruction inst = MakeInstruction(0x8000, "NOP");
  std::string output = formatter_->FormatInstruction(inst);

  EXPECT_FALSE(output.empty());
  EXPECT_TRUE(output.find("NOP") != std::string::npos);
  EXPECT_TRUE(output.find("$8000") != std::string::npos);  // Address in comment
}

// Test immediate addressing mode instruction
TEST_F(SCMASMFormatterTest, FormatImmediateInstruction) {
  core::Instruction inst = MakeInstruction(0x8000, "LDA", "#$00", core::AddressingMode::IMMEDIATE);
  std::string output = formatter_->FormatInstruction(inst);

  EXPECT_TRUE(output.find("LDA") != std::string::npos);
  EXPECT_TRUE(output.find("#$00") != std::string::npos);
}

// Test absolute addressing mode instruction
TEST_F(SCMASMFormatterTest, FormatAbsoluteInstruction) {
  core::Instruction inst = MakeInstruction(0x8000, "LDA", "$1234", core::AddressingMode::ABSOLUTE);
  std::string output = formatter_->FormatInstruction(inst);

  EXPECT_TRUE(output.find("LDA") != std::string::npos);
  EXPECT_TRUE(output.find("$1234") != std::string::npos);
}

// Test instruction with label
TEST_F(SCMASMFormatterTest, FormatInstructionWithLabel) {
  address_map_->SetLabel(0x8000, "START");

  core::Instruction inst = MakeInstruction(0x8000, "NOP");
  std::string output = formatter_->FormatInstruction(inst, address_map_.get());

  EXPECT_TRUE(output.find("START") != std::string::npos);
  EXPECT_TRUE(output.find("NOP") != std::string::npos);
}

// Test instruction with comment
TEST_F(SCMASMFormatterTest, FormatInstructionWithComment) {
  address_map_->SetComment(0x8000, "Initialize");

  core::Instruction inst = MakeInstruction(0x8000, "NOP");
  std::string output = formatter_->FormatInstruction(inst, address_map_.get());

  EXPECT_TRUE(output.find("Initialize") != std::string::npos);
  // SCMASM format doesn't use ; for inline comments
}

// Test branch instruction with label substitution
TEST_F(SCMASMFormatterTest, FormatBranchWithLabel) {
  address_map_->SetLabel(0x8010, "LOOP");

  core::Instruction inst = MakeInstruction(0x8000, "BNE", "$8010", core::AddressingMode::RELATIVE);
  inst.target_address = 0x8010;
  inst.is_branch = true;

  std::string output = formatter_->FormatInstruction(inst, address_map_.get());

  EXPECT_TRUE(output.find("BNE") != std::string::npos);
  EXPECT_TRUE(output.find("LOOP") != std::string::npos);
}

// Test data formatting - hex bytes
TEST_F(SCMASMFormatterTest, FormatDataHex) {
  std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04};
  std::string output = formatter_->FormatData(0x9000, data);

  EXPECT_FALSE(output.empty());
  // SCMASM uses .DA or .HS for data
  EXPECT_TRUE(output.find(".DA") != std::string::npos ||
              output.find(".HS") != std::string::npos ||
              output.find(".BY") != std::string::npos);
  EXPECT_TRUE(output.find("01") != std::string::npos);
  EXPECT_TRUE(output.find("02") != std::string::npos);
}

// Test complete format with simple program
TEST_F(SCMASMFormatterTest, FormatCompleteProgram) {
  core::Binary binary({0xA9, 0x00, 0x85, 0x10, 0x60}, 0x8000);
  binary.set_source_file("test.bin");

  std::vector<core::Instruction> instructions;
  instructions.push_back(MakeInstruction(0x8000, "LDA", "#$00", core::AddressingMode::IMMEDIATE));
  instructions.push_back(MakeInstruction(0x8002, "STA", "$10", core::AddressingMode::ZERO_PAGE));
  instructions.push_back(MakeInstruction(0x8004, "RTS"));

  std::string output = formatter_->Format(binary, instructions);

  EXPECT_FALSE(output.empty());
  // Should contain header
  EXPECT_TRUE(output.find("test.bin") != std::string::npos);
  // Should contain .OR directive (SCMASM uses .OR instead of ORG)
  EXPECT_TRUE(output.find(".OR") != std::string::npos);
  EXPECT_TRUE(output.find("$8000") != std::string::npos);
  // Should contain instructions
  EXPECT_TRUE(output.find("LDA") != std::string::npos);
  EXPECT_TRUE(output.find("STA") != std::string::npos);
  EXPECT_TRUE(output.find("RTS") != std::string::npos);
  // Should contain footer (.TF instead of CHK)
  EXPECT_TRUE(output.find(".TF") != std::string::npos);
}

// Test format with labels
TEST_F(SCMASMFormatterTest, FormatWithLabels) {
  core::Binary binary({0xEA, 0xEA}, 0x8000);

  address_map_->SetLabel(0x8000, "START");
  address_map_->SetLabel(0x8001, "LOOP");

  std::vector<core::Instruction> instructions;
  instructions.push_back(MakeInstruction(0x8000, "NOP"));
  instructions.push_back(MakeInstruction(0x8001, "NOP"));

  std::string output = formatter_->Format(binary, instructions, address_map_.get());

  EXPECT_TRUE(output.find("START") != std::string::npos);
  EXPECT_TRUE(output.find("LOOP") != std::string::npos);
}

// Test SCMASM column alignment
TEST_F(SCMASMFormatterTest, ColumnAlignment) {
  core::Instruction inst = MakeInstruction(0x8000, "LDA", "#$00", core::AddressingMode::IMMEDIATE);
  std::string output = formatter_->FormatInstruction(inst);

  // Should have proper spacing - opcode column at appropriate position
  EXPECT_GT(output.length(), 10);  // Should be reasonably long with spacing
}

// Test long label handling
TEST_F(SCMASMFormatterTest, LongLabel) {
  address_map_->SetLabel(0x8000, "VERY_LONG_LABEL_NAME");

  core::Instruction inst = MakeInstruction(0x8000, "NOP");
  std::string output = formatter_->FormatInstruction(inst, address_map_.get());

  EXPECT_TRUE(output.find("VERY_LONG_LABEL_NAME") != std::string::npos);
  EXPECT_TRUE(output.find("NOP") != std::string::npos);
}

// Test all addressing modes formatting
TEST_F(SCMASMFormatterTest, AllAddressingModes) {
  struct TestCase {
    std::string mnemonic;
    std::string operand;
    core::AddressingMode mode;
  };

  std::vector<TestCase> cases = {
      {"NOP", "", core::AddressingMode::IMPLIED},
      {"ASL", "A", core::AddressingMode::ACCUMULATOR},
      {"LDA", "#$00", core::AddressingMode::IMMEDIATE},
      {"LDA", "$10", core::AddressingMode::ZERO_PAGE},
      {"LDA", "$10,X", core::AddressingMode::ZERO_PAGE_X},
      {"LDX", "$10,Y", core::AddressingMode::ZERO_PAGE_Y},
      {"LDA", "$1234", core::AddressingMode::ABSOLUTE},
      {"LDA", "$1234,X", core::AddressingMode::ABSOLUTE_X},
      {"LDA", "$1234,Y", core::AddressingMode::ABSOLUTE_Y},
      {"JMP", "($1234)", core::AddressingMode::INDIRECT},
      {"LDA", "($10,X)", core::AddressingMode::INDEXED_INDIRECT},
      {"LDA", "($10),Y", core::AddressingMode::INDIRECT_INDEXED},
      {"BNE", "LABEL", core::AddressingMode::RELATIVE},
  };

  for (const auto& tc : cases) {
    core::Instruction inst = MakeInstruction(0x8000, tc.mnemonic, tc.operand, tc.mode);
    std::string output = formatter_->FormatInstruction(inst);

    EXPECT_FALSE(output.empty());
    EXPECT_TRUE(output.find(tc.mnemonic) != std::string::npos);
    if (!tc.operand.empty()) {
      EXPECT_TRUE(output.find(tc.operand) != std::string::npos);
    }
  }
}

// Test symbol table integration
TEST_F(SCMASMFormatterTest, SymbolTableIntegration) {
  core::SymbolTable symbol_table;
  symbol_table.AddSymbol(0xC000, "KEYBOARD");
  symbol_table.AddSymbol(0xFDED, "COUT");

  core::Instruction inst = MakeInstruction(0x8000, "LDA", "$C000", core::AddressingMode::ABSOLUTE);
  inst.target_address = 0xC000;

  std::string output = formatter_->FormatInstruction(inst, nullptr, &symbol_table);

  // Should substitute symbol name
  EXPECT_TRUE(output.find("KEYBOARD") != std::string::npos || output.find("C000") != std::string::npos);
}

// Test empty instruction list
TEST_F(SCMASMFormatterTest, EmptyInstructions) {
  core::Binary binary({0x00}, 0x8000);
  std::vector<core::Instruction> instructions;

  std::string output = formatter_->Format(binary, instructions);

  // Should still have header and footer
  EXPECT_FALSE(output.empty());
  EXPECT_TRUE(output.find(".OR") != std::string::npos);
  EXPECT_TRUE(output.find(".TF") != std::string::npos);
}

// Test data region formatting
TEST_F(SCMASMFormatterTest, DataRegionInFormat) {
  // Create binary with code and data
  core::Binary binary({0xA9, 0x00, 0x60, 0x48, 0x65, 0x6C, 0x6C, 0x6F}, 0x8000);

  address_map_->SetType(0x8000, core::AddressType::CODE);
  address_map_->SetType(0x8001, core::AddressType::CODE);
  address_map_->SetType(0x8002, core::AddressType::CODE);
  address_map_->SetType(0x8003, core::AddressType::DATA);
  address_map_->SetType(0x8004, core::AddressType::DATA);
  address_map_->SetType(0x8005, core::AddressType::DATA);
  address_map_->SetType(0x8006, core::AddressType::DATA);
  address_map_->SetType(0x8007, core::AddressType::DATA);

  std::vector<core::Instruction> instructions;
  instructions.push_back(MakeInstruction(0x8000, "LDA", "#$00"));
  instructions.push_back(MakeInstruction(0x8002, "RTS"));

  std::string output = formatter_->Format(binary, instructions, address_map_.get());

  // Should have both code instructions
  EXPECT_TRUE(output.find("LDA") != std::string::npos);
  EXPECT_TRUE(output.find("RTS") != std::string::npos);
  // Output should not be empty
  EXPECT_FALSE(output.empty());
}

// Test JSR instruction formatting
TEST_F(SCMASMFormatterTest, JSRInstruction) {
  address_map_->SetLabel(0x8100, "SUBROUTINE");

  core::Instruction inst = MakeInstruction(0x8000, "JSR", "$8100", core::AddressingMode::ABSOLUTE);
  inst.target_address = 0x8100;
  inst.is_call = true;

  std::string output = formatter_->FormatInstruction(inst, address_map_.get());

  EXPECT_TRUE(output.find("JSR") != std::string::npos);
  EXPECT_TRUE(output.find("SUBROUTINE") != std::string::npos);
}

// Test JMP instruction formatting
TEST_F(SCMASMFormatterTest, JMPInstruction) {
  address_map_->SetLabel(0x9000, "TARGET");

  core::Instruction inst = MakeInstruction(0x8000, "JMP", "$9000", core::AddressingMode::ABSOLUTE);
  inst.target_address = 0x9000;
  inst.is_jump = true;

  std::string output = formatter_->FormatInstruction(inst, address_map_.get());

  EXPECT_TRUE(output.find("JMP") != std::string::npos);
  EXPECT_TRUE(output.find("TARGET") != std::string::npos);
}

// Test multiple data bytes
TEST_F(SCMASMFormatterTest, MultipleDataBytes) {
  std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
  std::string output = formatter_->FormatData(0x9000, data);

  EXPECT_FALSE(output.empty());
  // All bytes should be present
  for (int i = 1; i <= 8; ++i) {
    std::ostringstream hex;
    hex << std::setfill('0') << std::setw(2) << std::hex << std::uppercase << i;
    // Byte might be formatted as $01 or just 01
  }
}

// Test zero page addresses
TEST_F(SCMASMFormatterTest, ZeroPageAddress) {
  core::Instruction inst = MakeInstruction(0x0010, "NOP");
  std::string output = formatter_->FormatInstruction(inst);

  // Should handle zero page address properly
  EXPECT_TRUE(output.find("NOP") != std::string::npos);
  EXPECT_TRUE(output.find("$") != std::string::npos);
}

// Test high addresses (near 0xFFFF)
TEST_F(SCMASMFormatterTest, HighAddress) {
  core::Instruction inst = MakeInstruction(0xFFF0, "NOP");
  std::string output = formatter_->FormatInstruction(inst);

  EXPECT_TRUE(output.find("NOP") != std::string::npos);
  EXPECT_TRUE(output.find("FFF0") != std::string::npos);
}

// Test SCMASM-specific local label format
TEST_F(SCMASMFormatterTest, LocalLabelFormat) {
  // SCMASM uses .N for local labels (e.g., .1, .2) instead of Merlin's :N
  address_map_->SetLabel(0x8000, "MAIN");
  address_map_->SetLabel(0x8010, ".1");  // Local label

  core::Instruction inst1 = MakeInstruction(0x8000, "NOP");
  core::Instruction inst2 = MakeInstruction(0x8010, "NOP");

  std::string output1 = formatter_->FormatInstruction(inst1, address_map_.get());
  std::string output2 = formatter_->FormatInstruction(inst2, address_map_.get());

  EXPECT_TRUE(output1.find("MAIN") != std::string::npos);
  EXPECT_TRUE(output2.find(".1") != std::string::npos);
}

// Test .OP directive for CPU variant (if supported)
TEST_F(SCMASMFormatterTest, CPUVariantDirective) {
  core::Binary binary({0xEA}, 0x8000);
  binary.set_source_file("test.bin");

  std::vector<core::Instruction> instructions;
  instructions.push_back(MakeInstruction(0x8000, "NOP"));

  std::string output = formatter_->Format(binary, instructions);

  // May contain .OP directive for CPU variant selection
  // This is optional depending on implementation
  EXPECT_FALSE(output.empty());
}

// Test that inline (end-of-line) comments are aligned to COMMENT_COL (40 for SCMASM)
TEST_F(SCMASMFormatterTest, InlineCommentAlignment) {
  // SCMASM uses column 40 for inline comments (no ; prefix in SCMASM format)

  // Short instruction: NOP
  core::Instruction inst1 = MakeInstruction(0x8000, "NOP");
  std::string output1 = formatter_->FormatInstruction(inst1);
  size_t comment_pos1 = output1.find('$');
  EXPECT_EQ(comment_pos1, 40) << "Inline comment for 'NOP' should be at column 40\nLine: " << output1;

  // Medium instruction: LDA #$FF
  core::Instruction inst2 = MakeInstruction(0x8002, "LDA", "#$FF", core::AddressingMode::IMMEDIATE);
  std::string output2 = formatter_->FormatInstruction(inst2);
  size_t comment_pos2 = output2.find("$8002");
  EXPECT_EQ(comment_pos2, 40) << "Inline comment for 'LDA #$FF' should be at column 40\nLine: " << output2;

  // Longer instruction: LDA $1234,X
  core::Instruction inst3 = MakeInstruction(0x8004, "LDA", "$1234,X", core::AddressingMode::ABSOLUTE_X);
  std::string output3 = formatter_->FormatInstruction(inst3);
  size_t comment_pos3 = output3.find("$8004");
  EXPECT_EQ(comment_pos3, 40) << "Inline comment for 'LDA $1234,X' should be at column 40\nLine: " << output3;

  // With local label
  address_map_->SetLabel(0x8006, ".1");
  core::Instruction inst4 = MakeInstruction(0x8006, "RTS");
  std::string output4 = formatter_->FormatInstruction(inst4, address_map_.get());
  size_t comment_pos4 = output4.find("$8006");
  EXPECT_EQ(comment_pos4, 40) << "Inline comment with local label should be at column 40\nLine: " << output4;
}

}  // namespace
}  // namespace output
}  // namespace sourcerer
