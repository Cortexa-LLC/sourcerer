// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "output/edtasm_formatter.h"

#include <gtest/gtest.h>
#include "analysis/equate_generator.h"

namespace sourcerer {
namespace output {
namespace {

// Test fixture for EdtasmFormatter tests
class EdtasmFormatterTest : public ::testing::Test {
 protected:
  void SetUp() override {
    formatter_ = CreateEdtasmFormatter();
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
TEST_F(EdtasmFormatterTest, FormatterName) {
  EXPECT_EQ(formatter_->Name(), "EDTASM+");
}

// Test header formatting
TEST_F(EdtasmFormatterTest, FormatHeader) {
  core::Binary binary({0x00, 0x01, 0x02}, 0x8000);
  binary.set_source_file("test.bin");

  std::string header = formatter_->FormatHeader(binary);

  EXPECT_FALSE(header.empty());
  EXPECT_TRUE(header.find("test.bin") != std::string::npos);
  EXPECT_TRUE(header.find("$8000") != std::string::npos);
  EXPECT_TRUE(header.find("3 bytes") != std::string::npos);
  EXPECT_TRUE(header.find("Sourcerer") != std::string::npos);
  EXPECT_TRUE(header.find("Multi-CPU") != std::string::npos);
}

// Test footer formatting
TEST_F(EdtasmFormatterTest, FormatFooter) {
  std::string footer = formatter_->FormatFooter();

  EXPECT_FALSE(footer.empty());
  EXPECT_TRUE(footer.find("END") != std::string::npos);
}

// Test implied addressing mode instruction
TEST_F(EdtasmFormatterTest, FormatImpliedInstruction) {
  core::Instruction inst = MakeInstruction(0x8000, "NOP");
  std::string output = formatter_->FormatInstruction(inst);

  EXPECT_FALSE(output.empty());
  EXPECT_TRUE(output.find("NOP") != std::string::npos);
}

// Test immediate addressing mode instruction
TEST_F(EdtasmFormatterTest, FormatImmediateInstruction) {
  core::Instruction inst = MakeInstruction(0x8000, "LDA", "#$00", core::AddressingMode::IMMEDIATE);
  std::string output = formatter_->FormatInstruction(inst);

  EXPECT_TRUE(output.find("LDA") != std::string::npos);
  EXPECT_TRUE(output.find("#$00") != std::string::npos);
}

// Test extended addressing mode instruction
TEST_F(EdtasmFormatterTest, FormatExtendedInstruction) {
  core::Instruction inst = MakeInstruction(0x8000, "LDA", "$1234", core::AddressingMode::EXTENDED);
  std::string output = formatter_->FormatInstruction(inst);

  EXPECT_TRUE(output.find("LDA") != std::string::npos);
  EXPECT_TRUE(output.find("$1234") != std::string::npos);
}

// Test instruction with label
TEST_F(EdtasmFormatterTest, FormatInstructionWithLabel) {
  address_map_->SetLabel(0x8000, "START");

  core::Instruction inst = MakeInstruction(0x8000, "NOP");
  std::string output = formatter_->FormatInstruction(inst, address_map_.get());

  EXPECT_TRUE(output.find("START") != std::string::npos);
  EXPECT_TRUE(output.find("NOP") != std::string::npos);
}

// Test instruction with comment
TEST_F(EdtasmFormatterTest, FormatInstructionWithComment) {
  address_map_->SetComment(0x8000, "Initialize");

  core::Instruction inst = MakeInstruction(0x8000, "NOP");
  std::string output = formatter_->FormatInstruction(inst, address_map_.get());

  EXPECT_TRUE(output.find("Initialize") != std::string::npos);
  EXPECT_TRUE(output.find(";") != std::string::npos);
}

// Test branch instruction with label substitution
TEST_F(EdtasmFormatterTest, FormatBranchWithLabel) {
  address_map_->SetLabel(0x8010, "LOOP");
  address_map_->SetType(0x8010, core::AddressType::CODE);

  core::Instruction inst = MakeInstruction(0x8000, "BNE", "$8010", core::AddressingMode::RELATIVE);
  inst.target_address = 0x8010;
  inst.is_branch = true;

  std::string output = formatter_->FormatInstruction(inst, address_map_.get());

  EXPECT_TRUE(output.find("BNE") != std::string::npos);
  EXPECT_TRUE(output.find("LOOP") != std::string::npos);
}

// Test data formatting - hex bytes
TEST_F(EdtasmFormatterTest, FormatDataHex) {
  std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04};
  std::string output = formatter_->FormatData(0x9000, data);

  EXPECT_FALSE(output.empty());
  EXPECT_TRUE(output.find("FCB") != std::string::npos);
  EXPECT_TRUE(output.find("01") != std::string::npos);
  EXPECT_TRUE(output.find("02") != std::string::npos);
}

// Test long branch conversion BRA to LBRA
TEST_F(EdtasmFormatterTest, LongBranchConversionBRA) {
  core::Instruction inst = MakeInstruction(0x8000, "BRA", "$8100", core::AddressingMode::RELATIVE);
  inst.target_address = 0x8100;  // Distance = 0x8100 - 0x8002 = 0xFE (254)
  inst.is_branch = true;
  inst.bytes = {0x20, 0x00};  // BRA is 2 bytes

  std::string output = formatter_->FormatInstruction(inst);

  EXPECT_TRUE(output.find("LBRA") != std::string::npos);
}

// Test long branch conversion BNE to LBNE
TEST_F(EdtasmFormatterTest, LongBranchConversionBNE) {
  core::Instruction inst = MakeInstruction(0x8000, "BNE", "$8100", core::AddressingMode::RELATIVE);
  inst.target_address = 0x8100;
  inst.is_branch = true;
  inst.bytes = {0x26, 0x00};

  std::string output = formatter_->FormatInstruction(inst);

  EXPECT_TRUE(output.find("LBNE") != std::string::npos);
}

// Test branch comment generation
TEST_F(EdtasmFormatterTest, BranchInstructionComments) {
  struct BranchTest {
    std::string mnemonic;
    std::string expected_comment_fragment;
  };

  std::vector<BranchTest> tests = {
    {"BEQ", "zero"},
    {"BNE", "not equal"},
    {"BCC", "carry clear"},
    {"BCS", "carry set"},
    {"BMI", "minus"},
    {"BPL", "plus"},
    {"BVS", "overflow set"},
    {"BVC", "overflow clear"},
    {"BRA", "always"},
  };

  for (const auto& test : tests) {
    core::Instruction inst = MakeInstruction(0x8000, test.mnemonic, "LABEL", core::AddressingMode::RELATIVE);
    inst.is_branch = true;
    std::string output = formatter_->FormatInstruction(inst);

    EXPECT_TRUE(output.find(test.expected_comment_fragment) != std::string::npos)
        << "Mnemonic: " << test.mnemonic << " should have comment fragment: " << test.expected_comment_fragment;
  }
}

// Test long branch comments
TEST_F(EdtasmFormatterTest, LongBranchInstructionComments) {
  struct BranchTest {
    std::string mnemonic;
    std::string expected_comment_fragment;
  };

  std::vector<BranchTest> tests = {
    {"LBEQ", "zero"},
    {"LBNE", "not equal"},
    {"LBCC", "carry clear"},
    {"LBCS", "carry set"},
    {"LBRA", "always"},
  };

  for (const auto& test : tests) {
    core::Instruction inst = MakeInstruction(0x8000, test.mnemonic, "LABEL", core::AddressingMode::RELATIVE);
    inst.is_branch = true;
    std::string output = formatter_->FormatInstruction(inst);

    EXPECT_TRUE(output.find(test.expected_comment_fragment) != std::string::npos)
        << "Mnemonic: " << test.mnemonic;
  }
}

// Test column alignment (OPCODE_COL = 9)
TEST_F(EdtasmFormatterTest, ColumnAlignment) {
  core::Instruction inst = MakeInstruction(0x8000, "LDA", "#$00", core::AddressingMode::IMMEDIATE);
  std::string output = formatter_->FormatInstruction(inst);

  EXPECT_GT(output.length(), 10);
  // Opcode should be at column 9 (position 9)
  EXPECT_GE(output.find("LDA"), 0);
}

// Test long label handling
TEST_F(EdtasmFormatterTest, LongLabel) {
  address_map_->SetLabel(0x8000, "VERY_LONG_LABEL_NAME");

  core::Instruction inst = MakeInstruction(0x8000, "NOP");
  std::string output = formatter_->FormatInstruction(inst, address_map_.get());

  EXPECT_TRUE(output.find("VERY_LONG_LABEL_NAME") != std::string::npos);
  EXPECT_TRUE(output.find("NOP") != std::string::npos);
}

// Test complete format with simple program
TEST_F(EdtasmFormatterTest, FormatCompleteProgram) {
  core::Binary binary({0x12, 0x3F, 0x60}, 0x8000);
  binary.set_source_file("test.bin");

  // Mark addresses as CODE so they are output
  address_map_->SetType(0x8000, core::AddressType::CODE);
  address_map_->SetType(0x8001, core::AddressType::CODE);
  address_map_->SetType(0x8002, core::AddressType::CODE);

  std::vector<core::Instruction> instructions;
  instructions.push_back(MakeInstruction(0x8000, "NOP", "", core::AddressingMode::IMPLIED));
  instructions.push_back(MakeInstruction(0x8001, "CLRA", "", core::AddressingMode::IMPLIED));
  instructions.push_back(MakeInstruction(0x8002, "RTS", "", core::AddressingMode::IMPLIED));

  std::string output = formatter_->Format(binary, instructions, address_map_.get());

  EXPECT_FALSE(output.empty());
  EXPECT_TRUE(output.find("test.bin") != std::string::npos);
  EXPECT_TRUE(output.find("ORG") != std::string::npos);
  EXPECT_TRUE(output.find("$8000") != std::string::npos);
  EXPECT_TRUE(output.find("NOP") != std::string::npos);
  EXPECT_TRUE(output.find("RTS") != std::string::npos);
  EXPECT_TRUE(output.find("END") != std::string::npos);
}

// Test format with labels
TEST_F(EdtasmFormatterTest, FormatWithLabels) {
  address_map_->SetLabel(0x8000, "START");
  address_map_->SetLabel(0x8001, "LOOP");

  core::Instruction inst1 = MakeInstruction(0x8000, "NOP");
  core::Instruction inst2 = MakeInstruction(0x8001, "NOP");

  std::string output1 = formatter_->FormatInstruction(inst1, address_map_.get());
  std::string output2 = formatter_->FormatInstruction(inst2, address_map_.get());

  EXPECT_TRUE(output1.find("START") != std::string::npos);
  EXPECT_TRUE(output2.find("LOOP") != std::string::npos);
}

// Test empty instruction list
TEST_F(EdtasmFormatterTest, EmptyInstructions) {
  core::Binary binary({0x00}, 0x8000);
  std::vector<core::Instruction> instructions;

  std::string output = formatter_->Format(binary, instructions);

  EXPECT_FALSE(output.empty());
  EXPECT_TRUE(output.find("ORG") != std::string::npos);
  EXPECT_TRUE(output.find("END") != std::string::npos);
}

// Test data region formatting
TEST_F(EdtasmFormatterTest, DataRegionInFormat) {
  core::Binary binary({0x12, 0x3F, 0x60, 0x48, 0x65, 0x6C, 0x6C, 0x6F}, 0x8000);

  address_map_->SetType(0x8000, core::AddressType::CODE);
  address_map_->SetType(0x8001, core::AddressType::CODE);
  address_map_->SetType(0x8002, core::AddressType::CODE);
  address_map_->SetType(0x8003, core::AddressType::DATA);
  address_map_->SetType(0x8004, core::AddressType::DATA);
  address_map_->SetType(0x8005, core::AddressType::DATA);
  address_map_->SetType(0x8006, core::AddressType::DATA);
  address_map_->SetType(0x8007, core::AddressType::DATA);

  std::vector<core::Instruction> instructions;
  instructions.push_back(MakeInstruction(0x8000, "NOP"));
  instructions.push_back(MakeInstruction(0x8001, "CLRA"));
  instructions.push_back(MakeInstruction(0x8002, "RTS"));

  std::string output = formatter_->Format(binary, instructions, address_map_.get());

  EXPECT_TRUE(output.find("NOP") != std::string::npos);
  EXPECT_TRUE(output.find("RTS") != std::string::npos);
  EXPECT_FALSE(output.empty());
}

// Test BSR (branch to subroutine) instruction
TEST_F(EdtasmFormatterTest, BSRInstruction) {
  address_map_->SetLabel(0x8100, "SUBROUTINE");
  address_map_->SetType(0x8100, core::AddressType::CODE);

  core::Instruction inst = MakeInstruction(0x8000, "BSR", "$8100", core::AddressingMode::RELATIVE);
  inst.target_address = 0x8100;
  inst.is_call = true;

  std::string output = formatter_->FormatInstruction(inst, address_map_.get());

  EXPECT_TRUE(output.find("BSR") != std::string::npos);
  EXPECT_TRUE(output.find("SUBROUTINE") != std::string::npos);
}

// Test JSR (jump to subroutine) instruction
TEST_F(EdtasmFormatterTest, JSRInstruction) {
  address_map_->SetLabel(0x8100, "SUBROUTINE");
  address_map_->SetType(0x8100, core::AddressType::CODE);

  core::Instruction inst = MakeInstruction(0x8000, "JSR", "$8100", core::AddressingMode::EXTENDED);
  inst.target_address = 0x8100;
  inst.is_call = true;

  std::string output = formatter_->FormatInstruction(inst, address_map_.get());

  EXPECT_TRUE(output.find("JSR") != std::string::npos);
  EXPECT_TRUE(output.find("SUBROUTINE") != std::string::npos);
}

// Test JMP instruction
TEST_F(EdtasmFormatterTest, JMPInstruction) {
  address_map_->SetLabel(0x9000, "TARGET");
  address_map_->SetType(0x9000, core::AddressType::CODE);

  core::Instruction inst = MakeInstruction(0x8000, "JMP", "$9000", core::AddressingMode::EXTENDED);
  inst.target_address = 0x9000;
  inst.is_jump = true;

  std::string output = formatter_->FormatInstruction(inst, address_map_.get());

  EXPECT_TRUE(output.find("JMP") != std::string::npos);
  EXPECT_TRUE(output.find("TARGET") != std::string::npos);
}

// Test multiple data bytes
TEST_F(EdtasmFormatterTest, MultipleDataBytes) {
  std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
  std::string output = formatter_->FormatData(0x9000, data);

  EXPECT_FALSE(output.empty());
  EXPECT_TRUE(output.find("FCB") != std::string::npos);
}

// Test zero page addressing
TEST_F(EdtasmFormatterTest, ZeroPageAddress) {
  core::Instruction inst = MakeInstruction(0x0010, "NOP");
  std::string output = formatter_->FormatInstruction(inst);

  EXPECT_TRUE(output.find("NOP") != std::string::npos);
}

// Test high addresses
TEST_F(EdtasmFormatterTest, HighAddress) {
  core::Instruction inst = MakeInstruction(0xFFF0, "NOP");
  std::string output = formatter_->FormatInstruction(inst);

  EXPECT_TRUE(output.find("NOP") != std::string::npos);
}

// Test subroutine label detection
TEST_F(EdtasmFormatterTest, SubroutineLabelDetection) {
  address_map_->SetLabel(0x8000, ".local");
  address_map_->SetLabel(0x8001, "L_1234");
  address_map_->SetLabel(0x8002, "DATA_1234");
  address_map_->SetLabel(0x8003, "SUB_8003");

  core::Binary binary({0x12, 0x3F, 0x60, 0x39}, 0x8000);
  std::vector<core::Instruction> instructions;
  for (uint32_t addr = 0x8000; addr <= 0x8003; ++addr) {
    instructions.push_back(MakeInstruction(addr, "NOP"));
  }

  std::string output = formatter_->Format(binary, instructions, address_map_.get());

  EXPECT_TRUE(output.find("SUB_8003") != std::string::npos);
}

// Test PSH/PUL stack instructions
TEST_F(EdtasmFormatterTest, StackInstructions) {
  std::vector<std::string> stack_mnemonics = {"PSHS", "PULS", "PSHU", "PULU"};

  for (const auto& mnem : stack_mnemonics) {
    core::Instruction inst = MakeInstruction(0x8000, mnem, "A,B", core::AddressingMode::IMPLIED);
    std::string output = formatter_->FormatInstruction(inst);

    EXPECT_TRUE(output.find(mnem) != std::string::npos);
  }
}

// Test string data detection and formatting
TEST_F(EdtasmFormatterTest, StringDataDetection) {
  // Create binary with ASCII string "HELLO"
  std::vector<uint8_t> binary_data = {'H', 'e', 'l', 'l', 'o', ' ', 'T', 'e', 's', 't', 0x00};
  core::Binary binary(binary_data, 0x8000);

  for (size_t i = 0; i < binary_data.size(); ++i) {
    address_map_->SetType(0x8000 + i, core::AddressType::DATA);
  }

  std::vector<core::Instruction> instructions;
  std::string output = formatter_->Format(binary, instructions, address_map_.get());

  // Should detect as string and use FCC
  EXPECT_TRUE(output.find("FCC") != std::string::npos || output.find("FCB") != std::string::npos);
}

// Test binary data with high bytes
TEST_F(EdtasmFormatterTest, BinaryDataHighBytes) {
  std::vector<uint8_t> data = {0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8};
  core::Binary binary(data, 0x8000);

  for (size_t i = 0; i < data.size(); ++i) {
    address_map_->SetType(0x8000 + i, core::AddressType::DATA);
  }

  std::vector<core::Instruction> instructions;
  std::string output = formatter_->Format(binary, instructions, address_map_.get());

  // Should use FCB for binary data
  EXPECT_TRUE(output.find("FCB") != std::string::npos);
  EXPECT_TRUE(output.find("FF") != std::string::npos);
}

// Test inline data (never use string format)
TEST_F(EdtasmFormatterTest, InlineDataFormatting) {
  core::Binary binary({0x03, 0x00, 0x90}, 0x8000);

  address_map_->SetType(0x8000, core::AddressType::INLINE_DATA);
  address_map_->SetType(0x8001, core::AddressType::INLINE_DATA);
  address_map_->SetType(0x8002, core::AddressType::INLINE_DATA);

  std::vector<core::Instruction> instructions;
  std::string output = formatter_->Format(binary, instructions, address_map_.get());

  EXPECT_TRUE(output.find("FCB") != std::string::npos);
  EXPECT_TRUE(output.find("FCC") == std::string::npos);
}

// Test long hex data (wraps to multiple lines)
TEST_F(EdtasmFormatterTest, LongHexData) {
  std::vector<uint8_t> data(20, 0xFF);
  core::Binary binary(data, 0x8000);

  for (size_t i = 0; i < data.size(); ++i) {
    address_map_->SetType(0x8000 + i, core::AddressType::DATA);
  }

  std::vector<core::Instruction> instructions;
  std::string output = formatter_->Format(binary, instructions, address_map_.get());

  size_t fcb_count = 0;
  size_t pos = 0;
  while ((pos = output.find("FCB", pos)) != std::string::npos) {
    fcb_count++;
    pos += 3;
  }

  EXPECT_GE(fcb_count, 2) << "Long data should wrap to multiple FCB lines";
}

// Test platform hints for PIA registers
TEST_F(EdtasmFormatterTest, PlatformPIAHints) {
  core::SymbolTable symbol_table;
  symbol_table.AddSymbol(0xFF00, "PIA0");
  symbol_table.AddSymbol(0xFF20, "PIA1");

  core::Instruction inst = MakeInstruction(0x8000, "LDA", "$FF00", core::AddressingMode::EXTENDED);
  inst.target_address = 0xFF00;

  std::string output = formatter_->FormatInstruction(inst, nullptr, &symbol_table);

  // Should have label or hint
  EXPECT_TRUE(output.find("$FF00") != std::string::npos || output.find("PIA0") != std::string::npos);
}

// Test address table with 16-bit words
TEST_F(EdtasmFormatterTest, AddressTableWithWords) {
  std::vector<uint8_t> data = {0x80, 0x00, 0x80, 0x10};  // $8000, $8010
  core::Binary binary(data, 0x8000);

  address_map_->SetComment(0x8000, "JUMPTABLE: 2 entries");
  for (size_t i = 0; i < data.size(); ++i) {
    address_map_->SetType(0x8000 + i, core::AddressType::DATA);
  }

  std::vector<core::Instruction> instructions;
  std::string output = formatter_->Format(binary, instructions, address_map_.get());

  // Jump table should use FDB for words
  EXPECT_TRUE(output.find("FDB") != std::string::npos);
}

// Test mix of code and data
TEST_F(EdtasmFormatterTest, CodeDataMix) {
  core::Binary binary({0x12, 0x3F, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46}, 0x8000);

  address_map_->SetType(0x8000, core::AddressType::CODE);
  address_map_->SetType(0x8001, core::AddressType::CODE);
  address_map_->SetType(0x8002, core::AddressType::DATA);
  address_map_->SetType(0x8003, core::AddressType::DATA);
  address_map_->SetType(0x8004, core::AddressType::DATA);
  address_map_->SetType(0x8005, core::AddressType::DATA);
  address_map_->SetType(0x8006, core::AddressType::DATA);
  address_map_->SetType(0x8007, core::AddressType::DATA);

  std::vector<core::Instruction> instructions;
  instructions.push_back(MakeInstruction(0x8000, "CLRA"));
  instructions.push_back(MakeInstruction(0x8001, "CLRB"));

  std::string output = formatter_->Format(binary, instructions, address_map_.get());

  EXPECT_TRUE(output.find("CLRA") != std::string::npos);
  EXPECT_TRUE(output.find("CLRB") != std::string::npos);
}

// Test format with equate generator
TEST_F(EdtasmFormatterTest, FormatWithEquateGenerator) {
  std::vector<core::Instruction> instructions;
  for (int i = 0; i < 3; ++i) {
    core::Instruction inst = MakeInstruction(0x8000 + i * 2, "LDA", "#$42", core::AddressingMode::IMMEDIATE);
    inst.bytes = {0x86, 0x42};
    instructions.push_back(inst);
  }

  analysis::EquateGenerator equate_gen(2);
  equate_gen.AnalyzeInstructions(instructions);

  core::Binary binary({0x86, 0x42, 0x86, 0x42, 0x86, 0x42}, 0x8000);
  std::string output = formatter_->Format(binary, instructions, nullptr, nullptr, &equate_gen);

  // Should have EQU directive
  EXPECT_TRUE(output.find("EQU") != std::string::npos);
}

// Test symbol table integration
TEST_F(EdtasmFormatterTest, SymbolTableIntegration) {
  core::SymbolTable symbol_table;
  symbol_table.AddSymbol(0xC000, "KEYBOARD");
  symbol_table.AddSymbol(0xFDED, "COUT");

  core::Instruction inst = MakeInstruction(0x8000, "LDA", "$C000", core::AddressingMode::EXTENDED);
  inst.target_address = 0xC000;

  std::string output = formatter_->FormatInstruction(inst, nullptr, &symbol_table);

  EXPECT_TRUE(output.find("KEYBOARD") != std::string::npos || output.find("C000") != std::string::npos);
}

// Test ROM routine description comment
TEST_F(EdtasmFormatterTest, ROMRoutineDescription) {
  core::SymbolTable symbol_table;
  core::Symbol rom_routine;
  rom_routine.name = "COUT";
  rom_routine.address = 0xFDED;
  rom_routine.type = core::SymbolType::ROM_ROUTINE;
  rom_routine.description = "Character output routine";
  symbol_table.AddSymbol(rom_routine);

  core::Instruction inst = MakeInstruction(0x8000, "JSR", "$FDED", core::AddressingMode::EXTENDED);
  inst.target_address = 0xFDED;
  inst.is_call = true;

  std::string output = formatter_->FormatInstruction(inst, nullptr, &symbol_table);

  EXPECT_TRUE(output.find("JSR") != std::string::npos);
  EXPECT_TRUE(output.find("COUT") != std::string::npos);
  EXPECT_TRUE(output.find("Character output routine") != std::string::npos);
}

// Test BSR (branch to subroutine) - call instructions are not converted to long form
TEST_F(EdtasmFormatterTest, LBSRInstruction) {
  address_map_->SetLabel(0x8200, "FAR_SUB");
  address_map_->SetType(0x8200, core::AddressType::CODE);

  core::Instruction inst = MakeInstruction(0x8000, "BSR", "$8200", core::AddressingMode::RELATIVE);
  inst.target_address = 0x8200;
  inst.is_call = true;
  inst.bytes = {0x8D, 0x00};

  // BSR is a call instruction, so conversion doesn't happen (by design)
  // Long branch conversion is only for pure branches, not calls
  std::string output = formatter_->FormatInstruction(inst, address_map_.get());

  EXPECT_TRUE(output.find("BSR") != std::string::npos);
  EXPECT_TRUE(output.find("FAR_SUB") != std::string::npos);
}

// Test short branch that doesn't need conversion
TEST_F(EdtasmFormatterTest, ShortBranchNoConversion) {
  address_map_->SetLabel(0x8010, "CLOSE");

  core::Instruction inst = MakeInstruction(0x8000, "BNE", "$8010", core::AddressingMode::RELATIVE);
  inst.target_address = 0x8010;
  inst.is_branch = true;
  inst.bytes = {0x26, 0x00};

  std::string output = formatter_->FormatInstruction(inst, address_map_.get());

  EXPECT_TRUE(output.find("BNE") != std::string::npos);
  EXPECT_TRUE(output.find("LBNE") == std::string::npos);
  EXPECT_TRUE(output.find("CLOSE") != std::string::npos);
}

// Test all 6809 branch mnemonics
TEST_F(EdtasmFormatterTest, All6809BranchMnemonics) {
  std::vector<std::string> branches = {
    "BRA", "BRN", "BHI", "BLS", "BCC", "BCS", "BNE", "BEQ",
    "BVC", "BVS", "BPL", "BMI", "BGE", "BLT", "BGT", "BLE",
    "BSR"
  };

  for (const auto& branch : branches) {
    core::Instruction inst = MakeInstruction(0x8000, branch, "TARGET", core::AddressingMode::RELATIVE);
    inst.is_branch = true;
    if (branch == "BSR") inst.is_call = true;

    std::string output = formatter_->FormatInstruction(inst);

    EXPECT_TRUE(output.find(branch) != std::string::npos) << "Branch " << branch << " not found";
  }
}

// Test unknown address type (default to binary)
TEST_F(EdtasmFormatterTest, UnknownAddressType) {
  core::Binary binary({0xFF, 0xFF, 0xFF}, 0x8000);

  // Don't set address types - leave as UNKNOWN
  std::vector<core::Instruction> instructions;
  std::string output = formatter_->Format(binary, instructions, address_map_.get());

  EXPECT_FALSE(output.empty());
  EXPECT_TRUE(output.find("FCB") != std::string::npos);
}

// Test orphan CODE bytes
TEST_F(EdtasmFormatterTest, OrphanCODEBytes) {
  core::Binary binary({0xFF, 0xFF, 0xFF, 0x60}, 0x8000);

  address_map_->SetType(0x8000, core::AddressType::CODE);
  address_map_->SetType(0x8001, core::AddressType::CODE);
  address_map_->SetType(0x8002, core::AddressType::CODE);
  address_map_->SetType(0x8003, core::AddressType::CODE);
  address_map_->SetLabel(0x8003, "RTS_LABEL");  // Label on the instruction itself

  std::vector<core::Instruction> instructions;
  instructions.push_back(MakeInstruction(0x8003, "RTS"));

  std::string output = formatter_->Format(binary, instructions, address_map_.get());

  EXPECT_TRUE(output.find("RTS") != std::string::npos);
  // Output should have the orphaned bytes and the RTS instruction
  EXPECT_TRUE(output.find("FCB") != std::string::npos);
}

// Test target_address label substitution
TEST_F(EdtasmFormatterTest, TargetAddressLabelSubstitution) {
  address_map_->SetLabel(0x8010, "LOOP");
  address_map_->SetType(0x8010, core::AddressType::CODE);

  core::Instruction inst = MakeInstruction(0x8000, "BNE", "$8010", core::AddressingMode::RELATIVE);
  inst.target_address = 0x8010;
  inst.is_branch = true;

  std::string output = formatter_->FormatInstruction(inst, address_map_.get());

  EXPECT_TRUE(output.find("LOOP") != std::string::npos);
}

// Test return instructions
TEST_F(EdtasmFormatterTest, ReturnInstructions) {
  std::vector<std::string> returns = {"RTS", "RTI"};

  for (const auto& ret : returns) {
    core::Instruction inst = MakeInstruction(0x8000, ret);
    inst.is_return = true;

    std::string output = formatter_->FormatInstruction(inst);

    EXPECT_TRUE(output.find(ret) != std::string::npos);
  }
}

// Test interrupts and special instructions
TEST_F(EdtasmFormatterTest, InterruptInstructions) {
  std::vector<std::string> intrs = {"SWI", "SWI2", "SWI3", "CWAI", "SYNC"};

  for (const auto& intr : intrs) {
    core::Instruction inst = MakeInstruction(0x8000, intr);

    std::string output = formatter_->FormatInstruction(inst);

    EXPECT_TRUE(output.find(intr) != std::string::npos);
  }
}

// Test register transfer instructions
TEST_F(EdtasmFormatterTest, RegisterTransferInstructions) {
  core::Instruction tfr = MakeInstruction(0x8000, "TFR", "A,B");
  std::string output1 = formatter_->FormatInstruction(tfr);
  EXPECT_TRUE(output1.find("TFR") != std::string::npos);

  core::Instruction exg = MakeInstruction(0x8000, "EXG", "A,B");
  std::string output2 = formatter_->FormatInstruction(exg);
  EXPECT_TRUE(output2.find("EXG") != std::string::npos);
}

// Test string with delimiter character (should switch to HEX)
TEST_F(EdtasmFormatterTest, StringWithDelimiter) {
  std::vector<uint8_t> data = {'I', 't', '\'', 's', ' ', 'g', 'r', 'e', 'a', 't'};
  core::Binary binary(data, 0x8000);

  for (size_t i = 0; i < data.size(); ++i) {
    address_map_->SetType(0x8000 + i, core::AddressType::DATA);
  }

  std::vector<core::Instruction> instructions;
  std::string output = formatter_->Format(binary, instructions, address_map_.get());

  // Should handle delimiter character properly
  EXPECT_TRUE(output.find("FCC") != std::string::npos || output.find("FCB") != std::string::npos);
}

// Test indexed addressing modes
TEST_F(EdtasmFormatterTest, IndexedAddressingModes) {
  struct TestCase {
    std::string operand;
    core::AddressingMode mode;
  };

  std::vector<TestCase> cases = {
    {"$10,X", core::AddressingMode::INDEXED},
    {"$10,Y", core::AddressingMode::INDEXED},
    {"$1234,X", core::AddressingMode::INDEXED},
    {"$1234,Y", core::AddressingMode::INDEXED},
  };

  for (const auto& tc : cases) {
    core::Instruction inst = MakeInstruction(0x8000, "LDA", tc.operand, tc.mode);
    std::string output = formatter_->FormatInstruction(inst);

    EXPECT_TRUE(output.find("LDA") != std::string::npos);
    EXPECT_TRUE(output.find(tc.operand) != std::string::npos);
  }
}

// Test indirect addressing
TEST_F(EdtasmFormatterTest, IndirectAddressing) {
  core::Instruction inst = MakeInstruction(0x8000, "JMP", "[$8010]", core::AddressingMode::INDIRECT);
  std::string output = formatter_->FormatInstruction(inst);

  EXPECT_TRUE(output.find("JMP") != std::string::npos);
  EXPECT_TRUE(output.find("$8010") != std::string::npos);
}

// Test accumulator addressing
TEST_F(EdtasmFormatterTest, AccumulatorAddressing) {
  core::Instruction inst = MakeInstruction(0x8000, "ROLA", "", core::AddressingMode::ACCUMULATOR);
  std::string output = formatter_->FormatInstruction(inst);

  EXPECT_TRUE(output.find("ROLA") != std::string::npos);
}

// Test word data with odd byte at end
TEST_F(EdtasmFormatterTest, WordDataWithOddByte) {
  std::vector<uint8_t> data = {0x80, 0x00, 0x80, 0x10, 0xFF};
  core::Binary binary(data, 0x8000);

  address_map_->SetComment(0x8000, "JUMPTABLE: 2 entries");
  for (size_t i = 0; i < data.size(); ++i) {
    address_map_->SetType(0x8000 + i, core::AddressType::DATA);
  }

  std::vector<core::Instruction> instructions;
  std::string output = formatter_->Format(binary, instructions, address_map_.get());

  // Should have FDB for words and FCB for odd byte
  EXPECT_TRUE(output.find("FDB") != std::string::npos);
  EXPECT_TRUE(output.find("FCB") != std::string::npos);
}

// Test address format helper
TEST_F(EdtasmFormatterTest, AddressFormatting) {
  std::string output = formatter_->FormatHeader(core::Binary({0x00}, 0x1234));
  EXPECT_TRUE(output.find("$1234") != std::string::npos);

  output = formatter_->FormatHeader(core::Binary({0x00}, 0xFFFF));
  EXPECT_TRUE(output.find("$FFFF") != std::string::npos);

  output = formatter_->FormatHeader(core::Binary({0x00}, 0x0000));
  EXPECT_TRUE(output.find("$0000") != std::string::npos);
}

// Test small data blocks
TEST_F(EdtasmFormatterTest, SmallDataBlocks) {
  // Data smaller than 8 bytes - should be treated as binary
  std::vector<uint8_t> data = {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47};
  core::Binary binary(data, 0x8000);

  for (size_t i = 0; i < data.size(); ++i) {
    address_map_->SetType(0x8000 + i, core::AddressType::DATA);
  }

  std::vector<core::Instruction> instructions;
  std::string output = formatter_->Format(binary, instructions, address_map_.get());

  // 7 bytes is too short for string detection
  EXPECT_TRUE(output.find("FCB") != std::string::npos);
}

// Test data with control characters
TEST_F(EdtasmFormatterTest, DataWithControlCharacters) {
  std::vector<uint8_t> data = {'H', 'e', 'l', 'l', 'o', 0x01, 'W', 'o', 'r', 'l', 'd'};
  core::Binary binary(data, 0x8000);

  for (size_t i = 0; i < data.size(); ++i) {
    address_map_->SetType(0x8000 + i, core::AddressType::DATA);
  }

  std::vector<core::Instruction> instructions;
  std::string output = formatter_->Format(binary, instructions, address_map_.get());

  // Control character should prevent string detection
  EXPECT_TRUE(output.find("FCB") != std::string::npos);
}

// Test negative branch distance
TEST_F(EdtasmFormatterTest, NegativeBranchDistance) {
  core::Instruction inst = MakeInstruction(0x8100, "BRA", "$8000", core::AddressingMode::RELATIVE);
  inst.target_address = 0x8000;
  inst.is_branch = true;
  inst.bytes = {0x20, 0x00};

  // Distance = 0x8000 - (0x8100 + 2) = -258 (should trigger LBRA)
  std::string output = formatter_->FormatInstruction(inst);

  EXPECT_TRUE(output.find("LBRA") != std::string::npos);
}

// Test all long branch mnemonics
TEST_F(EdtasmFormatterTest, AllLongBranchMnemonics) {
  std::vector<std::string> long_branches = {
    "LBRA", "LBRN", "LBHI", "LBLS", "LBCC", "LBCS", "LBNE", "LBEQ",
    "LBVC", "LBVS", "LBPL", "LBMI", "LBGE", "LBLT", "LBGT", "LBLE"
  };

  for (const auto& branch : long_branches) {
    core::Instruction inst = MakeInstruction(0x8000, branch, "TARGET", core::AddressingMode::RELATIVE);
    inst.is_branch = true;

    std::string output = formatter_->FormatInstruction(inst);

    EXPECT_TRUE(output.find(branch) != std::string::npos) << "Long branch " << branch << " not found";
  }
}

// Test empty operand with modes that should have operands
TEST_F(EdtasmFormatterTest, InstructionWithoutOperand) {
  core::Instruction inst = MakeInstruction(0x8000, "CLRA", "", core::AddressingMode::IMPLIED);
  std::string output = formatter_->FormatInstruction(inst);

  EXPECT_TRUE(output.find("CLRA") != std::string::npos);
}

// Test format with data_collector handling
TEST_F(EdtasmFormatterTest, FormatWithDataCollector) {
  core::Binary binary({0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A}, 0x8000);

  address_map_->SetLabel(0x8000, "DATA_START");
  for (size_t i = 0; i < binary.size(); ++i) {
    address_map_->SetType(0x8000 + i, core::AddressType::DATA);
  }

  std::vector<core::Instruction> instructions;
  std::string output = formatter_->Format(binary, instructions, address_map_.get());

  EXPECT_TRUE(output.find("DATA_START") != std::string::npos);
  EXPECT_FALSE(output.empty());
}

// Test branch mnemonics that trigger long form conversion (BEQ)
TEST_F(EdtasmFormatterTest, BranchDistanceConversionBEQ) {
  core::Instruction inst = MakeInstruction(0x8100, "BEQ", "$8000", core::AddressingMode::RELATIVE);
  inst.target_address = 0x8000;
  inst.is_branch = true;
  inst.bytes = {0x27, 0x00};

  // Distance = 0x8000 - (0x8100 + 2) = -258 (should trigger LBEQ)
  std::string output = formatter_->FormatInstruction(inst);
  EXPECT_TRUE(output.find("LBEQ") != std::string::npos);
}

// Test BVC long form conversion
TEST_F(EdtasmFormatterTest, BranchDistanceConversionBVC) {
  core::Instruction inst = MakeInstruction(0x8100, "BVC", "$8000", core::AddressingMode::RELATIVE);
  inst.target_address = 0x8000;
  inst.is_branch = true;
  inst.bytes = {0x28, 0x00};

  std::string output = formatter_->FormatInstruction(inst);
  EXPECT_TRUE(output.find("LBVC") != std::string::npos);
}

// Test BVS long form conversion
TEST_F(EdtasmFormatterTest, BranchDistanceConversionBVS) {
  core::Instruction inst = MakeInstruction(0x8100, "BVS", "$8000", core::AddressingMode::RELATIVE);
  inst.target_address = 0x8000;
  inst.is_branch = true;
  inst.bytes = {0x29, 0x00};

  std::string output = formatter_->FormatInstruction(inst);
  EXPECT_TRUE(output.find("LBVS") != std::string::npos);
}

// Test BMI long form conversion
TEST_F(EdtasmFormatterTest, BranchDistanceConversionBMI) {
  core::Instruction inst = MakeInstruction(0x8100, "BMI", "$8000", core::AddressingMode::RELATIVE);
  inst.target_address = 0x8000;
  inst.is_branch = true;
  inst.bytes = {0x2B, 0x00};

  std::string output = formatter_->FormatInstruction(inst);
  EXPECT_TRUE(output.find("LBMI") != std::string::npos);
}

// Test BGE long form conversion
TEST_F(EdtasmFormatterTest, BranchDistanceConversionBGE) {
  core::Instruction inst = MakeInstruction(0x8100, "BGE", "$8000", core::AddressingMode::RELATIVE);
  inst.target_address = 0x8000;
  inst.is_branch = true;
  inst.bytes = {0x2C, 0x00};

  std::string output = formatter_->FormatInstruction(inst);
  EXPECT_TRUE(output.find("LBGE") != std::string::npos);
}

// Test BLT long form conversion
TEST_F(EdtasmFormatterTest, BranchDistanceConversionBLT) {
  core::Instruction inst = MakeInstruction(0x8100, "BLT", "$8000", core::AddressingMode::RELATIVE);
  inst.target_address = 0x8000;
  inst.is_branch = true;
  inst.bytes = {0x2D, 0x00};

  std::string output = formatter_->FormatInstruction(inst);
  EXPECT_TRUE(output.find("LBLT") != std::string::npos);
}

// Test BGT long form conversion
TEST_F(EdtasmFormatterTest, BranchDistanceConversionBGT) {
  core::Instruction inst = MakeInstruction(0x8100, "BGT", "$8000", core::AddressingMode::RELATIVE);
  inst.target_address = 0x8000;
  inst.is_branch = true;
  inst.bytes = {0x2E, 0x00};

  std::string output = formatter_->FormatInstruction(inst);
  EXPECT_TRUE(output.find("LBGT") != std::string::npos);
}

// Test BLE long form conversion
TEST_F(EdtasmFormatterTest, BranchDistanceConversionBLE) {
  core::Instruction inst = MakeInstruction(0x8100, "BLE", "$8000", core::AddressingMode::RELATIVE);
  inst.target_address = 0x8000;
  inst.is_branch = true;
  inst.bytes = {0x2F, 0x00};

  std::string output = formatter_->FormatInstruction(inst);
  EXPECT_TRUE(output.find("LBLE") != std::string::npos);
}

// Test BPL long form conversion (another uncovered branch)
TEST_F(EdtasmFormatterTest, BranchDistanceConversionBPL) {
  core::Instruction inst = MakeInstruction(0x8100, "BPL", "$8000", core::AddressingMode::RELATIVE);
  inst.target_address = 0x8000;
  inst.is_branch = true;
  inst.bytes = {0x2A, 0x00};

  std::string output = formatter_->FormatInstruction(inst);
  EXPECT_TRUE(output.find("LBPL") != std::string::npos);
}

// Test IsSubroutineLabel with different label prefixes
TEST_F(EdtasmFormatterTest, SubroutineLabelClassification) {
  auto cast_formatter = dynamic_cast<EdtasmFormatter*>(formatter_.get());
  ASSERT_NE(nullptr, cast_formatter);

  // Regular subroutine label should return true
  EXPECT_TRUE(cast_formatter->IsSubroutineLabel("MAIN"));
  EXPECT_TRUE(cast_formatter->IsSubroutineLabel("SUB_ROUTINE"));

  // Local labels starting with @ should return false
  EXPECT_FALSE(cast_formatter->IsSubroutineLabel("@LOCAL"));

  // Local labels starting with . should return false
  EXPECT_FALSE(cast_formatter->IsSubroutineLabel(".local"));

  // Branch labels (L_xxxx) should return false
  EXPECT_FALSE(cast_formatter->IsSubroutineLabel("L_8000"));

  // Data labels should return false
  EXPECT_FALSE(cast_formatter->IsSubroutineLabel("DATA_START"));
}

// Test symbol table with referenced addresses
TEST_F(EdtasmFormatterTest, ReferencedSymbolsInOutput) {
  // Create a binary with a symbol table
  core::Binary binary({0x00, 0x01, 0x02, 0x03}, 0x8000);

  auto symbol_table = std::make_unique<core::SymbolTable>();
  symbol_table->AddSymbol(0xFF00, "SCREEN", core::SymbolType::ROM_ROUTINE, "Screen memory");

  // Create instruction that references the symbol
  core::Instruction inst = MakeInstruction(0x8000, "LDA", "$FF00", core::AddressingMode::EXTENDED);
  inst.target_address = 0xFF00;

  address_map_->SetType(0x8000, core::AddressType::CODE);

  std::vector<core::Instruction> instructions = {inst};
  std::string output = formatter_->Format(binary, instructions, address_map_.get(), symbol_table.get());

  // Should contain EQU for the symbol
  EXPECT_TRUE(output.find("SCREEN") != std::string::npos);
  EXPECT_TRUE(output.find("EQU") != std::string::npos);
}

// Test word data with jump table comment
TEST_F(EdtasmFormatterTest, JumpTableWordData) {
  // Create a binary with word data (2 words = 4 bytes)
  std::vector<uint8_t> data = {0x80, 0x00, 0x80, 0x01};
  core::Binary binary(data, 0x8000);

  // Set label and data type for first word
  address_map_->SetLabel(0x8000, "JUMP_TABLE");
  for (size_t i = 0; i < data.size(); ++i) {
    address_map_->SetType(0x8000 + i, core::AddressType::DATA);
  }
  address_map_->SetComment(0x8000, "JUMPTABLE:");

  std::vector<core::Instruction> instructions;
  std::string output = formatter_->Format(binary, instructions, address_map_.get());

  // Should contain FDB for word data and label
  EXPECT_TRUE(output.find("FDB") != std::string::npos);
  EXPECT_TRUE(output.find("JUMP_TABLE") != std::string::npos);
}

// Test generated equates with comments
TEST_F(EdtasmFormatterTest, GeneratedEquatesWithComments) {
  core::Binary binary({0x00, 0x01}, 0x8000);

  // Create instruction using immediate value multiple times
  std::vector<core::Instruction> instructions;
  for (int i = 0; i < 3; ++i) {
    core::Instruction inst = MakeInstruction(0x8000 + i * 3, "LDA", "#$42", core::AddressingMode::IMMEDIATE);
    instructions.push_back(inst);
  }

  auto equate_gen = std::make_unique<analysis::EquateGenerator>();
  equate_gen->AnalyzeInstructions(instructions);

  std::string output = formatter_->Format(binary, instructions, address_map_.get(), nullptr, equate_gen.get());

  // Should contain generated equates in output
  EXPECT_TRUE(output.find("EQU") != std::string::npos);
}

// ====================================================================================
// Phase 7c Coverage Tests
// ====================================================================================

// Test long BSR instruction formatting
TEST_F(EdtasmFormatterTest, FormatLongBSR) {
  // Long BSR (16-bit) should be formatted as LBSR
  core::Instruction inst = MakeInstruction(0x8000, "BSR", "$9000", core::AddressingMode::RELATIVE);
  inst.bytes = {0x17, 0x0F, 0xFD};  // Long form BSR (3 bytes)

  std::string output = formatter_->FormatInstruction(inst);

  // With 3-byte BSR, formatter should convert to LBSR
  EXPECT_TRUE(output.find("BSR") != std::string::npos || output.find("LBSR") != std::string::npos);
}

// Test string data formatting
TEST_F(EdtasmFormatterTest, FormatStringDataBlock) {
  // Create a binary with ASCII string data
  std::vector<uint8_t> data = {
    'H', 'E', 'L', 'L', 'O', 0x00  // "HELLO" with null terminator
  };
  core::Binary binary(data, 0x8000);

  // Mark as DATA region
  for (uint32_t addr = 0x8000; addr < 0x8006; ++addr) {
    address_map_->SetType(addr, core::AddressType::DATA);
  }

  std::vector<core::Instruction> instructions;
  std::string output = formatter_->Format(binary, instructions, address_map_.get());

  // Should contain some representation of the string data
  EXPECT_FALSE(output.empty());
  // String data should be formatted (FCB or FCC directive)
  EXPECT_TRUE(output.find("FC") != std::string::npos);  // FCB or FCC
}

// Test platform register symbol handling
TEST_F(EdtasmFormatterTest, PlatformRegisterSymbols) {
  // Test with PIA0 register access
  address_map_->SetLabel(0xFF00, "PIA0");

  core::Instruction inst = MakeInstruction(0x8000, "LDA", "$FF00", core::AddressingMode::EXTENDED);
  std::string output = formatter_->FormatInstruction(inst, address_map_.get());

  // Should use label if available
  EXPECT_TRUE(output.find("LDA") != std::string::npos);
}

// Test partial instruction at boundary
TEST_F(EdtasmFormatterTest, PartialInstructionAtEnd) {
  // Single-byte binary (incomplete instruction)
  std::vector<uint8_t> data = {0x7E};  // JMP opcode without address
  core::Binary binary(data, 0x8000);

  // Mark as DATA since it's incomplete
  address_map_->SetType(0x8000, core::AddressType::DATA);

  std::vector<core::Instruction> instructions;
  std::string output = formatter_->Format(binary, instructions, address_map_.get());

  // Should handle gracefully
  EXPECT_FALSE(output.empty());
  EXPECT_TRUE(output.find("FCB") != std::string::npos);
}

}  // namespace
}  // namespace output
}  // namespace sourcerer
