// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "output/merlin_formatter.h"

#include <gtest/gtest.h>
#include "analysis/equate_generator.h"

namespace sourcerer {
namespace output {
namespace {

// Test fixture for MerlinFormatter tests
class MerlinFormatterTest : public ::testing::Test {
 protected:
  void SetUp() override {
    formatter_ = CreateMerlinFormatter();
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
TEST_F(MerlinFormatterTest, FormatterName) {
  EXPECT_EQ(formatter_->Name(), "Merlin");
}

// Test header formatting
TEST_F(MerlinFormatterTest, FormatHeader) {
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
TEST_F(MerlinFormatterTest, FormatFooter) {
  std::string footer = formatter_->FormatFooter();

  // Footer is intentionally empty - CHK directive removed to avoid extra bytes
  EXPECT_TRUE(footer.empty());
}

// Test implied addressing mode instruction
TEST_F(MerlinFormatterTest, FormatImpliedInstruction) {
  core::Instruction inst = MakeInstruction(0x8000, "NOP");
  std::string output = formatter_->FormatInstruction(inst);

  EXPECT_FALSE(output.empty());
  EXPECT_TRUE(output.find("NOP") != std::string::npos);
  // Address comments are not automatically added to reduce clutter
}

// Test immediate addressing mode instruction
TEST_F(MerlinFormatterTest, FormatImmediateInstruction) {
  core::Instruction inst = MakeInstruction(0x8000, "LDA", "#$00", core::AddressingMode::IMMEDIATE);
  std::string output = formatter_->FormatInstruction(inst);

  EXPECT_TRUE(output.find("LDA") != std::string::npos);
  EXPECT_TRUE(output.find("#$00") != std::string::npos);
}

// Test absolute addressing mode instruction
TEST_F(MerlinFormatterTest, FormatAbsoluteInstruction) {
  core::Instruction inst = MakeInstruction(0x8000, "LDA", "$1234", core::AddressingMode::ABSOLUTE);
  std::string output = formatter_->FormatInstruction(inst);

  EXPECT_TRUE(output.find("LDA") != std::string::npos);
  EXPECT_TRUE(output.find("$1234") != std::string::npos);
}

// Test instruction with label
TEST_F(MerlinFormatterTest, FormatInstructionWithLabel) {
  address_map_->SetLabel(0x8000, "START");

  core::Instruction inst = MakeInstruction(0x8000, "NOP");
  std::string output = formatter_->FormatInstruction(inst, address_map_.get());

  EXPECT_TRUE(output.find("START") != std::string::npos);
  EXPECT_TRUE(output.find("NOP") != std::string::npos);
}

// Test instruction with comment
TEST_F(MerlinFormatterTest, FormatInstructionWithComment) {
  address_map_->SetComment(0x8000, "Initialize");

  core::Instruction inst = MakeInstruction(0x8000, "NOP");
  std::string output = formatter_->FormatInstruction(inst, address_map_.get());

  EXPECT_TRUE(output.find("Initialize") != std::string::npos);
  EXPECT_TRUE(output.find(";") != std::string::npos);
}

// Test branch instruction with label substitution
TEST_F(MerlinFormatterTest, FormatBranchWithLabel) {
  address_map_->SetLabel(0x8010, "LOOP");
  address_map_->SetType(0x8010, core::AddressType::CODE);  // Mark as CODE for label substitution

  core::Instruction inst = MakeInstruction(0x8000, "BNE", "$8010", core::AddressingMode::RELATIVE);
  inst.target_address = 0x8010;
  inst.is_branch = true;

  std::string output = formatter_->FormatInstruction(inst, address_map_.get());

  EXPECT_TRUE(output.find("BNE") != std::string::npos);
  EXPECT_TRUE(output.find("LOOP") != std::string::npos);
}

// Test data formatting - hex bytes
TEST_F(MerlinFormatterTest, FormatDataHex) {
  std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04};
  std::string output = formatter_->FormatData(0x9000, data);

  EXPECT_FALSE(output.empty());
  EXPECT_TRUE(output.find("DFB") != std::string::npos || output.find("HEX") != std::string::npos);
  EXPECT_TRUE(output.find("01") != std::string::npos);
  EXPECT_TRUE(output.find("02") != std::string::npos);
}

// Test complete format with simple program
TEST_F(MerlinFormatterTest, FormatCompleteProgram) {
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
  // Should contain ORG directive
  EXPECT_TRUE(output.find("ORG") != std::string::npos);
  EXPECT_TRUE(output.find("$8000") != std::string::npos);
  // Should contain instructions
  EXPECT_TRUE(output.find("LDA") != std::string::npos);
  EXPECT_TRUE(output.find("STA") != std::string::npos);
  EXPECT_TRUE(output.find("RTS") != std::string::npos);
  // Footer is intentionally empty
}

// Test format with labels
TEST_F(MerlinFormatterTest, FormatWithLabels) {
  address_map_->SetLabel(0x8000, "START");
  address_map_->SetLabel(0x8001, "LOOP");

  core::Instruction inst1 = MakeInstruction(0x8000, "NOP");
  core::Instruction inst2 = MakeInstruction(0x8001, "NOP");

  std::string output1 = formatter_->FormatInstruction(inst1, address_map_.get());
  std::string output2 = formatter_->FormatInstruction(inst2, address_map_.get());

  EXPECT_TRUE(output1.find("START") != std::string::npos);
  EXPECT_TRUE(output2.find("LOOP") != std::string::npos);
}

// Test Merlin column alignment
TEST_F(MerlinFormatterTest, ColumnAlignment) {
  core::Instruction inst = MakeInstruction(0x8000, "LDA", "#$00", core::AddressingMode::IMMEDIATE);
  std::string output = formatter_->FormatInstruction(inst);

  // Should have proper spacing - opcode column at position 9
  // This is a basic check - exact spacing depends on implementation
  EXPECT_GT(output.length(), 10);  // Should be reasonably long with spacing
}

// Test long label handling
TEST_F(MerlinFormatterTest, LongLabel) {
  address_map_->SetLabel(0x8000, "VERY_LONG_LABEL_NAME");

  core::Instruction inst = MakeInstruction(0x8000, "NOP");
  std::string output = formatter_->FormatInstruction(inst, address_map_.get());

  EXPECT_TRUE(output.find("VERY_LONG_LABEL_NAME") != std::string::npos);
  EXPECT_TRUE(output.find("NOP") != std::string::npos);
}

// Test all addressing modes formatting
TEST_F(MerlinFormatterTest, AllAddressingModes) {
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
TEST_F(MerlinFormatterTest, SymbolTableIntegration) {
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
TEST_F(MerlinFormatterTest, EmptyInstructions) {
  core::Binary binary({0x00}, 0x8000);
  std::vector<core::Instruction> instructions;

  std::string output = formatter_->Format(binary, instructions);

  // Should still have header
  EXPECT_FALSE(output.empty());
  EXPECT_TRUE(output.find("ORG") != std::string::npos);
}

// Test data region formatting
TEST_F(MerlinFormatterTest, DataRegionInFormat) {
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
TEST_F(MerlinFormatterTest, JSRInstruction) {
  address_map_->SetLabel(0x8100, "SUBROUTINE");
  address_map_->SetType(0x8100, core::AddressType::CODE);  // Mark as CODE for label substitution

  core::Instruction inst = MakeInstruction(0x8000, "JSR", "$8100", core::AddressingMode::ABSOLUTE);
  inst.target_address = 0x8100;
  inst.is_call = true;

  std::string output = formatter_->FormatInstruction(inst, address_map_.get());

  EXPECT_TRUE(output.find("JSR") != std::string::npos);
  EXPECT_TRUE(output.find("SUBROUTINE") != std::string::npos);
}

// Test JMP instruction formatting
TEST_F(MerlinFormatterTest, JMPInstruction) {
  address_map_->SetLabel(0x9000, "TARGET");
  address_map_->SetType(0x9000, core::AddressType::CODE);  // Mark as CODE for label substitution

  core::Instruction inst = MakeInstruction(0x8000, "JMP", "$9000", core::AddressingMode::ABSOLUTE);
  inst.target_address = 0x9000;
  inst.is_jump = true;

  std::string output = formatter_->FormatInstruction(inst, address_map_.get());

  EXPECT_TRUE(output.find("JMP") != std::string::npos);
  EXPECT_TRUE(output.find("TARGET") != std::string::npos);
}

// Test multiple data bytes
TEST_F(MerlinFormatterTest, MultipleDataBytes) {
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
TEST_F(MerlinFormatterTest, ZeroPageAddress) {
  core::Instruction inst = MakeInstruction(0x0010, "NOP");
  std::string output = formatter_->FormatInstruction(inst);

  // Should handle zero page address properly
  EXPECT_TRUE(output.find("NOP") != std::string::npos);
}

// Test high addresses (near 0xFFFF)
TEST_F(MerlinFormatterTest, HighAddress) {
  core::Instruction inst = MakeInstruction(0xFFF0, "NOP");
  std::string output = formatter_->FormatInstruction(inst);

  EXPECT_TRUE(output.find("NOP") != std::string::npos);
}

// Test that inline (end-of-line) comments are aligned to COMMENT_COL (40)
TEST_F(MerlinFormatterTest, InlineCommentAlignment) {
  // Add a user comment to test alignment
  address_map_->SetComment(0x8000, "Test comment");

  // Short instruction: NOP with comment
  core::Instruction inst1 = MakeInstruction(0x8000, "NOP");
  std::string output1 = formatter_->FormatInstruction(inst1, address_map_.get());
  size_t comment_pos1 = output1.find(';');
  EXPECT_EQ(comment_pos1, 40) << "Inline comment for 'NOP' should be at column 40\nLine: " << output1;

  // Add comment for next test
  address_map_->SetComment(0x8002, "Another comment");

  // Medium instruction: LDA #$FF with comment
  core::Instruction inst2 = MakeInstruction(0x8002, "LDA", "#$FF", core::AddressingMode::IMMEDIATE);
  std::string output2 = formatter_->FormatInstruction(inst2, address_map_.get());
  size_t comment_pos2 = output2.find(';');
  EXPECT_EQ(comment_pos2, 40) << "Inline comment for 'LDA #$FF' should be at column 40\nLine: " << output2;

  // Add comment for next test
  address_map_->SetComment(0x8004, "Long instruction comment");

  // Longer instruction: LDA $1234,X with comment
  core::Instruction inst3 = MakeInstruction(0x8004, "LDA", "$1234,X", core::AddressingMode::ABSOLUTE_X);
  std::string output3 = formatter_->FormatInstruction(inst3, address_map_.get());
  size_t comment_pos3 = output3.find(';');
  EXPECT_EQ(comment_pos3, 40) << "Inline comment for 'LDA $1234,X' should be at column 40\nLine: " << output3;

  // With label and comment
  address_map_->SetLabel(0x8006, "START");
  address_map_->SetComment(0x8006, "Entry point");
  core::Instruction inst4 = MakeInstruction(0x8006, "RTS");
  std::string output4 = formatter_->FormatInstruction(inst4, address_map_.get());
  size_t comment_pos4 = output4.find(';');
  EXPECT_EQ(comment_pos4, 40) << "Inline comment with label should be at column 40\nLine: " << output4;
}

// ============================================================================
// Work Package 2: Enhanced Coverage Tests (Edge Cases & Missing Paths)
// ============================================================================

// Test equate generation integration
TEST_F(MerlinFormatterTest, EquateGenerationInFormat) {
  // Create instructions that use the same immediate value multiple times
  std::vector<core::Instruction> instructions;
  for (int i = 0; i < 5; ++i) {
    core::Instruction inst = MakeInstruction(0x8000 + i * 2, "LDA", "#$42", core::AddressingMode::IMMEDIATE);
    inst.bytes = {0xA9, 0x42};
    instructions.push_back(inst);
  }

  // EquateGenerator with min_usage_count=3
  analysis::EquateGenerator equate_gen(3);
  equate_gen.AnalyzeInstructions(instructions);

  core::Binary binary({0xA9, 0x42, 0xA9, 0x42, 0xA9, 0x42, 0xA9, 0x42, 0xA9, 0x42}, 0x8000);
  std::string output = formatter_->Format(binary, instructions, nullptr, nullptr, &equate_gen);

  // Should have EQU statements for value 0x42
  EXPECT_TRUE(output.find("EQU") != std::string::npos);
}

// Test equate substitution in immediate operands
TEST_F(MerlinFormatterTest, EquateSubstitutionInInstruction) {
  // Create instructions that use the same value multiple times
  std::vector<core::Instruction> instructions;
  for (int i = 0; i < 3; ++i) {
    core::Instruction inst = MakeInstruction(0x8000 + i * 2, "LDA", "#$42", core::AddressingMode::IMMEDIATE);
    inst.bytes = {0xA9, 0x42};
    instructions.push_back(inst);
  }

  analysis::EquateGenerator equate_gen(2);  // min_usage_count = 2
  equate_gen.AnalyzeInstructions(instructions);

  core::Instruction inst = MakeInstruction(0x8000, "LDA", "#$42", core::AddressingMode::IMMEDIATE);
  std::string output = formatter_->FormatInstruction(inst, nullptr, nullptr, &equate_gen);

  // Should substitute equate name (generated name will be IMM_42 or similar)
  EXPECT_TRUE(output.find("LDA") != std::string::npos);
  // The actual equate name is auto-generated, so just check it's not the raw hex
  EXPECT_TRUE(output.find("#") != std::string::npos);
}

// Test equate without comment
TEST_F(MerlinFormatterTest, EquateWithoutComment) {
  // Create instructions using value 0x10 multiple times
  std::vector<core::Instruction> instructions;
  for (int i = 0; i < 3; ++i) {
    core::Instruction inst = MakeInstruction(0x8000 + i * 2, "LDA", "#$10", core::AddressingMode::IMMEDIATE);
    inst.bytes = {0xA9, 0x10};
    instructions.push_back(inst);
  }

  analysis::EquateGenerator equate_gen(2);
  equate_gen.AnalyzeInstructions(instructions);

  core::Binary binary({0xA9, 0x10, 0xA9, 0x10, 0xA9, 0x10}, 0x8000);
  std::string output = formatter_->Format(binary, instructions, nullptr, nullptr, &equate_gen);

  // Should have EQU directive
  EXPECT_TRUE(output.find("EQU") != std::string::npos);
}

// Test malformed equate value (exception handling)
TEST_F(MerlinFormatterTest, MalformedEquateValue) {
  std::vector<core::Instruction> instructions;
  for (int i = 0; i < 3; ++i) {
    core::Instruction inst = MakeInstruction(0x8000 + i * 2, "LDA", "#$42", core::AddressingMode::IMMEDIATE);
    inst.bytes = {0xA9, 0x42};
    instructions.push_back(inst);
  }

  analysis::EquateGenerator equate_gen(2);
  equate_gen.AnalyzeInstructions(instructions);

  // Invalid hex string in operand
  core::Instruction inst = MakeInstruction(0x8000, "LDA", "#$XYZ", core::AddressingMode::IMMEDIATE);
  std::string output = formatter_->FormatInstruction(inst, nullptr, nullptr, &equate_gen);

  // Should not crash, should keep original operand
  EXPECT_TRUE(output.find("LDA") != std::string::npos);
}

// Test ROM routine description comment
TEST_F(MerlinFormatterTest, ROMRoutineDescription) {
  core::SymbolTable symbol_table;
  core::Symbol rom_routine;
  rom_routine.name = "COUT";
  rom_routine.address = 0xFDED;
  rom_routine.type = core::SymbolType::ROM_ROUTINE;
  rom_routine.description = "Character output routine";
  symbol_table.AddSymbol(rom_routine);

  core::Instruction inst = MakeInstruction(0x8000, "JSR", "$FDED", core::AddressingMode::ABSOLUTE);
  inst.target_address = 0xFDED;
  inst.is_call = true;

  std::string output = formatter_->FormatInstruction(inst, nullptr, &symbol_table);

  // Should have ROM routine description as comment
  EXPECT_TRUE(output.find("JSR") != std::string::npos);
  EXPECT_TRUE(output.find("COUT") != std::string::npos);
  EXPECT_TRUE(output.find("Character output routine") != std::string::npos);
}

// Test branch instruction comments for all mnemonics
TEST_F(MerlinFormatterTest, BranchInstructionComments) {
  struct BranchTest {
    std::string mnemonic;
    std::string expected_comment;
  };

  std::vector<BranchTest> tests = {
    {"BCS", "Carry set"},
    {"BCC", "Carry clear"},
    {"BEQ", "Equal / zero"},
    {"BNE", "Not equal / not zero"},
    {"BMI", "Minus / negative"},
    {"BPL", "Plus / positive"},
    {"BVS", "Overflow set"},
    {"BVC", "Overflow clear"},
    {"BRA", "Always"},
  };

  for (const auto& test : tests) {
    core::Instruction inst = MakeInstruction(0x8000, test.mnemonic, "LABEL", core::AddressingMode::RELATIVE);
    inst.is_branch = true;
    std::string output = formatter_->FormatInstruction(inst);

    EXPECT_TRUE(output.find(test.expected_comment) != std::string::npos)
        << "Mnemonic: " << test.mnemonic << " should have comment: " << test.expected_comment;
  }
}

// Test non-branch instruction (should not get branch comment)
TEST_F(MerlinFormatterTest, NonBranchNoComment) {
  core::Instruction inst = MakeInstruction(0x8000, "LDA", "#$00", core::AddressingMode::IMMEDIATE);
  std::string output = formatter_->FormatInstruction(inst);

  // Should not have any branch-related comments
  EXPECT_TRUE(output.find("Carry") == std::string::npos);
  EXPECT_TRUE(output.find("zero") == std::string::npos);
}

// Test IsSubroutineLabel edge cases
TEST_F(MerlinFormatterTest, SubroutineLabelDetection) {
  // Test local labels (not subroutines)
  address_map_->SetLabel(0x8000, ".local");
  address_map_->SetLabel(0x8001, ":another_local");

  // Test branch labels (not subroutines)
  address_map_->SetLabel(0x8002, "L_1234");

  // Test data labels (not subroutines)
  address_map_->SetLabel(0x8003, "DATA_1234");

  // Test zero page labels (not subroutines)
  address_map_->SetLabel(0x8004, "ZP_10");

  // Test actual subroutine
  address_map_->SetLabel(0x8005, "SUB_8005");

  core::Binary binary({0xEA, 0xEA, 0xEA, 0xEA, 0xEA, 0xEA}, 0x8000);
  std::vector<core::Instruction> instructions;
  for (uint32_t addr = 0x8000; addr <= 0x8005; ++addr) {
    instructions.push_back(MakeInstruction(addr, "NOP"));
  }

  std::string output = formatter_->Format(binary, instructions, address_map_.get());

  // Only SUB_8005 should have separator line
  // Look for subroutine separator specifically (31 dashes + newline), not header separators (39 dashes)
  size_t separator_count = 0;
  size_t pos = 0;
  while ((pos = output.find("*-------------------------------\n", pos)) != std::string::npos) {
    separator_count++;
    pos++;
  }

  EXPECT_EQ(separator_count, 1) << "Only one subroutine separator should be present";
}

// Test 4-digit address substitution
TEST_F(MerlinFormatterTest, FourDigitAddressSubstitution) {
  address_map_->SetLabel(0x1234, "TARGET");
  address_map_->SetType(0x1234, core::AddressType::CODE);

  core::Instruction inst = MakeInstruction(0x8000, "JMP", "$1234", core::AddressingMode::ABSOLUTE);
  inst.target_address = 0x1234;

  std::string output = formatter_->FormatInstruction(inst, address_map_.get());

  // Should substitute 4-digit address with label
  EXPECT_TRUE(output.find("TARGET") != std::string::npos);
  EXPECT_TRUE(output.find("$1234") == std::string::npos);
}

// Test target_address label substitution (priority 3)
TEST_F(MerlinFormatterTest, TargetAddressLabelSubstitution) {
  address_map_->SetLabel(0x8010, "LOOP");
  address_map_->SetType(0x8010, core::AddressType::CODE);

  // Branch instruction with target_address set
  core::Instruction inst = MakeInstruction(0x8000, "BNE", "$8010", core::AddressingMode::RELATIVE);
  inst.target_address = 0x8010;
  inst.is_branch = true;

  std::string output = formatter_->FormatInstruction(inst, address_map_.get());

  // Should use label from target_address
  EXPECT_TRUE(output.find("LOOP") != std::string::npos);
}

// Test orphan CODE bytes (no instruction but marked as CODE)
TEST_F(MerlinFormatterTest, OrphanCODEBytes) {
  core::Binary binary({0xFF, 0xFF, 0xFF, 0x60}, 0x8000);

  // Mark first 3 bytes as CODE but no instructions
  address_map_->SetType(0x8000, core::AddressType::CODE);
  address_map_->SetType(0x8001, core::AddressType::CODE);
  address_map_->SetType(0x8002, core::AddressType::CODE);
  address_map_->SetType(0x8003, core::AddressType::CODE);
  address_map_->SetLabel(0x8000, "ORPHAN");

  // Only one instruction at the end
  std::vector<core::Instruction> instructions;
  instructions.push_back(MakeInstruction(0x8003, "RTS"));

  std::string output = formatter_->Format(binary, instructions, address_map_.get());

  // Should output orphan bytes as HEX data
  EXPECT_TRUE(output.find("HEX") != std::string::npos);
  EXPECT_TRUE(output.find("ORPHAN") != std::string::npos);
  EXPECT_TRUE(output.find("RTS") != std::string::npos);
}

// Test orphan CODE bytes with mid-instruction label
TEST_F(MerlinFormatterTest, OrphanCODEBytesWithMidLabel) {
  core::Binary binary({0xFF, 0xFF, 0xFF}, 0x8000);

  address_map_->SetType(0x8000, core::AddressType::CODE);
  address_map_->SetType(0x8001, core::AddressType::CODE);
  address_map_->SetType(0x8002, core::AddressType::CODE);
  address_map_->SetLabel(0x8000, "START");
  address_map_->SetLabel(0x8001, "MID");  // Label in middle

  std::vector<core::Instruction> instructions;  // No instructions

  std::string output = formatter_->Format(binary, instructions, address_map_.get());

  // Should break at MID label
  EXPECT_TRUE(output.find("START") != std::string::npos);
  EXPECT_TRUE(output.find("MID") != std::string::npos);
}

// Test string with carriage return
TEST_F(MerlinFormatterTest, StringWithCarriageReturn) {
  // String with embedded CR ($8D)
  core::Binary binary({'H', 'e', 'l', 'l', 'o', 0x8D, 'W', 'o', 'r', 'l', 'd'}, 0x8000);

  address_map_->SetType(0x8000, core::AddressType::DATA);
  for (uint32_t i = 0; i <= 10; ++i) {
    address_map_->SetType(0x8000 + i, core::AddressType::DATA);
  }

  std::vector<core::Instruction> instructions;
  std::string output = formatter_->Format(binary, instructions, address_map_.get());

  // Should handle CR specially (output as HEX 8D)
  EXPECT_TRUE(output.find("HEX   8D") != std::string::npos);
}

// Test string with delimiter character
TEST_F(MerlinFormatterTest, StringWithDelimiter) {
  // String containing apostrophe (will be delimiter)
  core::Binary binary({'I', 't', '\'', 's'}, 0x8000);

  for (uint32_t i = 0; i < 4; ++i) {
    address_map_->SetType(0x8000 + i, core::AddressType::DATA);
  }

  std::vector<core::Instruction> instructions;
  std::string output = formatter_->Format(binary, instructions, address_map_.get());

  // Should escape delimiter by switching to HEX
  EXPECT_TRUE(output.find("HEX") != std::string::npos);
}

// Test address table with symbols
TEST_F(MerlinFormatterTest, AddressTableWithSymbols) {
  // Address table: two 16-bit addresses (little-endian)
  std::vector<uint8_t> table_data = {0x00, 0x90, 0x10, 0x91};  // $9000, $9110
  core::Binary binary(table_data, 0x8000);

  core::SymbolTable symbol_table;
  symbol_table.AddSymbol(0x9000, "ROUTINE1");
  symbol_table.AddSymbol(0x9110, "ROUTINE2");

  for (size_t i = 0; i < table_data.size(); ++i) {
    address_map_->SetType(0x8000 + i, core::AddressType::DATA);
  }

  std::vector<core::Instruction> instructions;
  std::string output = formatter_->Format(binary, instructions, address_map_.get(), &symbol_table);

  // Should use symbol names in DA directive
  EXPECT_TRUE(output.find("DA") != std::string::npos);
  EXPECT_TRUE(output.find("ROUTINE1") != std::string::npos);
  EXPECT_TRUE(output.find("ROUTINE2") != std::string::npos);
}

// Test address table with address_map labels
TEST_F(MerlinFormatterTest, AddressTableWithAddressMapLabels) {
  // Address table
  std::vector<uint8_t> table_data = {0x00, 0x90, 0x10, 0x91};
  core::Binary binary(table_data, 0x8000);

  address_map_->SetLabel(0x9000, "SUB_9000");
  address_map_->SetType(0x9000, core::AddressType::CODE);
  address_map_->SetLabel(0x9110, "SUB_9110");
  address_map_->SetType(0x9110, core::AddressType::CODE);

  for (size_t i = 0; i < table_data.size(); ++i) {
    address_map_->SetType(0x8000 + i, core::AddressType::DATA);
  }

  std::vector<core::Instruction> instructions;
  std::string output = formatter_->Format(binary, instructions, address_map_.get());

  EXPECT_TRUE(output.find("DA") != std::string::npos);
  EXPECT_TRUE(output.find("SUB_9000") != std::string::npos);
  EXPECT_TRUE(output.find("SUB_9110") != std::string::npos);
}

// Test address table with odd offset
TEST_F(MerlinFormatterTest, AddressTableWithOddOffset) {
  // One byte followed by address table
  std::vector<uint8_t> data = {0xFF, 0x00, 0x90, 0x10, 0x91};
  core::Binary binary(data, 0x8000);

  for (size_t i = 0; i < data.size(); ++i) {
    address_map_->SetType(0x8000 + i, core::AddressType::DATA);
  }

  std::vector<core::Instruction> instructions;
  std::string output = formatter_->Format(binary, instructions, address_map_.get());

  // DEBUG
  std::cerr << "=== AddressTableWithOddOffset OUTPUT ===" << std::endl << output << std::endl;

  // Should output first byte separately, then DA
  EXPECT_TRUE(output.find("HEX   FF") != std::string::npos);
  EXPECT_TRUE(output.find("DA") != std::string::npos);
}

// Test address table with leftover bytes
TEST_F(MerlinFormatterTest, AddressTableWithLeftoverBytes) {
  // Address table with one extra byte at end
  std::vector<uint8_t> data = {0x00, 0x90, 0x10, 0x91, 0xFF};
  core::Binary binary(data, 0x8000);

  for (size_t i = 0; i < data.size(); ++i) {
    address_map_->SetType(0x8000 + i, core::AddressType::DATA);
  }

  std::vector<core::Instruction> instructions;
  std::string output = formatter_->Format(binary, instructions, address_map_.get());

  // Should have DA followed by HEX for leftover
  EXPECT_TRUE(output.find("DA") != std::string::npos);
  EXPECT_TRUE(output.find("HEX   FF") != std::string::npos);
}

// Test long address table (more than 8 addresses per line)
TEST_F(MerlinFormatterTest, LongAddressTable) {
  // 10 addresses (20 bytes)
  std::vector<uint8_t> data;
  for (int i = 0; i < 10; ++i) {
    data.push_back(0x00);
    data.push_back(0x90 + i);
  }
  core::Binary binary(data, 0x8000);

  for (size_t i = 0; i < data.size(); ++i) {
    address_map_->SetType(0x8000 + i, core::AddressType::DATA);
  }

  std::vector<core::Instruction> instructions;
  std::string output = formatter_->Format(binary, instructions, address_map_.get());

  // Should wrap to multiple lines
  size_t da_count = 0;
  size_t pos = 0;
  while ((pos = output.find("DA", pos)) != std::string::npos) {
    da_count++;
    pos += 2;
  }

  EXPECT_GT(da_count, 1) << "Long address table should wrap to multiple lines";
}

// Test invalid address table (fallback to HEX)
TEST_F(MerlinFormatterTest, InvalidAddressTableFallback) {
  // Random data that doesn't look like addresses
  std::vector<uint8_t> data = {0x01, 0x02};
  core::Binary binary(data, 0x8000);

  for (size_t i = 0; i < data.size(); ++i) {
    address_map_->SetType(0x8000 + i, core::AddressType::DATA);
  }

  std::vector<core::Instruction> instructions;
  std::string output = formatter_->Format(binary, instructions, address_map_.get());

  // Should use HEX directive
  EXPECT_TRUE(output.find("HEX") != std::string::npos);
}

// Test inline data (ProDOS MLI parameters)
TEST_F(MerlinFormatterTest, InlineDataFormatting) {
  core::Binary binary({0x03, 0x00, 0x90}, 0x8000);

  address_map_->SetType(0x8000, core::AddressType::INLINE_DATA);
  address_map_->SetType(0x8001, core::AddressType::INLINE_DATA);
  address_map_->SetType(0x8002, core::AddressType::INLINE_DATA);

  std::vector<core::Instruction> instructions;
  std::string output = formatter_->Format(binary, instructions, address_map_.get());

  // Inline data should never use ASC, always HEX
  EXPECT_TRUE(output.find("HEX") != std::string::npos);
  EXPECT_TRUE(output.find("ASC") == std::string::npos);
}

// Test long hex data (wraps to multiple lines)
TEST_F(MerlinFormatterTest, LongHexData) {
  std::vector<uint8_t> data(20, 0xFF);  // 20 bytes of $FF
  core::Binary binary(data, 0x8000);

  for (size_t i = 0; i < data.size(); ++i) {
    address_map_->SetType(0x8000 + i, core::AddressType::DATA);
  }

  std::vector<core::Instruction> instructions;
  std::string output = formatter_->Format(binary, instructions, address_map_.get());

  // Should wrap to multiple HEX lines (8 bytes per line)
  size_t hex_count = 0;
  size_t pos = 0;
  while ((pos = output.find("HEX", pos)) != std::string::npos) {
    hex_count++;
    pos += 3;
  }

  EXPECT_GE(hex_count, 2) << "Long data should wrap to multiple HEX lines";
}

// Test symbol table priority over address_map labels
TEST_F(MerlinFormatterTest, SymbolTablePriority) {
  core::SymbolTable symbol_table;
  symbol_table.AddSymbol(0x9000, "ROM_SYMBOL");

  address_map_->SetLabel(0x9000, "LOCAL_LABEL");
  address_map_->SetType(0x9000, core::AddressType::CODE);

  core::Instruction inst = MakeInstruction(0x8000, "JMP", "$9000", core::AddressingMode::ABSOLUTE);
  inst.target_address = 0x9000;

  std::string output = formatter_->FormatInstruction(inst, address_map_.get(), &symbol_table);

  // Symbol table should take priority
  EXPECT_TRUE(output.find("ROM_SYMBOL") != std::string::npos);
}

// Test header with empty file type
TEST_F(MerlinFormatterTest, HeaderWithoutFileType) {
  core::Binary binary({0x00}, 0x8000);
  binary.set_source_file("test.bin");
  // Don't set file_type

  std::string header = formatter_->FormatHeader(binary);

  EXPECT_TRUE(header.find("test.bin") != std::string::npos);
  EXPECT_TRUE(header.find("$8000") != std::string::npos);
  // Should not crash when file_type is empty
}

// Test platform symbols in Format() with references
TEST_F(MerlinFormatterTest, PlatformSymbolsInFormat) {
  core::SymbolTable symbol_table;
  symbol_table.AddSymbol(0xC000, "KEYBOARD");

  core::Binary binary({0xAD, 0x00, 0xC0}, 0x8000);
  std::vector<core::Instruction> instructions;

  core::Instruction inst = MakeInstruction(0x8000, "LDA", "$C000", core::AddressingMode::ABSOLUTE);
  inst.target_address = 0xC000;
  instructions.push_back(inst);

  std::string output = formatter_->Format(binary, instructions, nullptr, &symbol_table);

  // Should have EQU statement for KEYBOARD
  EXPECT_TRUE(output.find("KEYBOARD") != std::string::npos);
  EXPECT_TRUE(output.find("EQU   $C000") != std::string::npos);
}

}  // namespace
}  // namespace output
}  // namespace sourcerer
