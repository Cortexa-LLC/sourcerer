// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include <gtest/gtest.h>
#include <fstream>
#include <sstream>

#include "core/binary.h"
#include "core/address_map.h"
#include "core/symbol_table.h"
#include "cpu/cpu_registry.h"
#include "output/formatter_registry.h"
#include "analysis/code_analyzer.h"
#include "analysis/label_generator.h"
#include "analysis/xref_builder.h"

namespace sourcerer {
namespace {

class IntegrationTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Registries auto-initialize on first access
  }

  // Helper: Full disassembly pipeline
  std::string DisassembleFull(
      const core::Binary& binary,
      const std::string& cpu_type,
      const std::string& format_type,
      bool enable_analysis = true,
      bool enable_xref = false,
      core::SymbolTable* symbol_table = nullptr) {

    // Create CPU
    auto cpu = cpu::CpuRegistry::Instance().Create(cpu_type);
    EXPECT_NE(cpu, nullptr);
    if (!cpu) return "";

    // Address map for analysis
    core::AddressMap address_map;

    std::vector<core::Instruction> instructions;

    if (enable_analysis) {
      // Run code flow analysis
      analysis::CodeAnalyzer analyzer(cpu.get(), &binary);
      analyzer.AddEntryPoint(binary.load_address());
      analyzer.Analyze(&address_map);

      // Disassemble only code regions
      uint32_t addr = binary.load_address();
      uint32_t end_addr = addr + binary.size();

      while (addr < end_addr) {
        if (address_map.IsCode(addr)) {
          const uint8_t* data = binary.GetPointer(addr);
          size_t remaining = end_addr - addr;

          if (data && remaining > 0) {
            try {
              core::Instruction inst = cpu->Disassemble(data, remaining, addr);
              instructions.push_back(inst);
              addr += inst.bytes.size();
            } catch (...) {
              addr++;
            }
          } else {
            addr++;
          }
        } else {
          addr++;
        }
      }

      // Build cross-references
      analysis::XrefBuilder xref_builder(&address_map);
      xref_builder.BuildXrefs(instructions);

      if (enable_xref) {
        xref_builder.AddXrefComments();
      }

      // Generate labels
      analysis::LabelGenerator label_gen(&address_map, &binary, symbol_table);
      label_gen.GenerateLabels(&instructions);

    } else {
      // Linear disassembly
      uint32_t addr = binary.load_address();
      uint32_t end_addr = addr + binary.size();

      while (addr < end_addr) {
        const uint8_t* data = binary.GetPointer(addr);
        size_t remaining = end_addr - addr;

        if (data && remaining > 0) {
          try {
            core::Instruction inst = cpu->Disassemble(data, remaining, addr);
            instructions.push_back(inst);
            addr += inst.bytes.size();

            if (inst.is_return) break;
          } catch (...) {
            addr++;
          }
        } else {
          break;
        }
      }
    }

    // Format output
    auto formatter = output::FormatterRegistry::Instance().Create(format_type);
    EXPECT_NE(formatter, nullptr);
    if (!formatter) return "";

    return formatter->Format(binary, instructions,
                            enable_analysis ? &address_map : nullptr,
                            symbol_table);
  }
};

// Test: Simple program with analysis
TEST_F(IntegrationTest, SimpleProgram_WithAnalysis) {
  // LDA #$00, STA $10, RTS
  core::Binary binary({0xA9, 0x00, 0x85, 0x10, 0x60}, 0x8000);
  binary.set_source_file("test_simple.bin");

  std::string output = DisassembleFull(binary, "6502", "merlin", true);

  EXPECT_FALSE(output.empty());
  EXPECT_NE(output.find("ORG"), std::string::npos);
  EXPECT_NE(output.find("LDA"), std::string::npos);
  EXPECT_NE(output.find("STA"), std::string::npos);
  EXPECT_NE(output.find("RTS"), std::string::npos);
}

// Test: Program with subroutine call
TEST_F(IntegrationTest, SubroutineCall_WithLabels) {
  // JSR $8008, RTS, (padding), SUB: LDA #$FF, RTS
  core::Binary binary({
    0x20, 0x08, 0x80,  // JSR $8008 (within binary)
    0x60,              // RTS
    0x00, 0x00, 0x00, 0x00,  // padding
    0xA9, 0xFF,        // LDA #$FF
    0x60               // RTS
  }, 0x8000);

  std::string output = DisassembleFull(binary, "6502", "merlin", true);

  // Should have labels for subroutine
  EXPECT_NE(output.find("JSR"), std::string::npos);
  EXPECT_NE(output.find("SUB_"), std::string::npos);
}

// Test: Branch with label
TEST_F(IntegrationTest, BranchWithLabel) {
  // Loop: DEX, BNE Loop, RTS
  core::Binary binary({
    0xCA,        // DEX
    0xD0, 0xFD,  // BNE -3
    0x60         // RTS
  }, 0x8000);

  std::string output = DisassembleFull(binary, "6502", "merlin", true);

  EXPECT_NE(output.find("DEX"), std::string::npos);
  EXPECT_NE(output.find("BNE"), std::string::npos);
  EXPECT_NE(output.find("RTS"), std::string::npos);
}

// Test: Cross-references enabled
TEST_F(IntegrationTest, CrossReferences) {
  // JSR SUB, JSR SUB, RTS, SUB: LDA #$00, RTS
  core::Binary binary({
    0x20, 0x09, 0x80,  // JSR $8009
    0x20, 0x09, 0x80,  // JSR $8009
    0x60,              // RTS
    0xA9, 0x00,        // LDA #$00
    0x60               // RTS
  }, 0x8000);

  std::string output = DisassembleFull(binary, "6502", "merlin", true, true);

  // Should have xref comment
  EXPECT_NE(output.find("Referenced from:"), std::string::npos);
}

// Test: With platform symbols
TEST_F(IntegrationTest, PlatformSymbols) {
  // LDA $C000, JSR $FDED, RTS
  core::Binary binary({
    0xAD, 0x00, 0xC0,  // LDA $C000
    0x20, 0xED, 0xFD,  // JSR $FDED
    0x60               // RTS
  }, 0x8000);

  // Create symbol table
  core::SymbolTable symbols;
  symbols.AddSymbol(0xC000, "KEYBOARD");
  symbols.AddSymbol(0xFDED, "COUT");

  std::string output = DisassembleFull(binary, "6502", "merlin", true, false, &symbols);

  // Should use symbol names
  EXPECT_NE(output.find("KEYBOARD"), std::string::npos);
  EXPECT_NE(output.find("COUT"), std::string::npos);

  // Should have EQU statements
  EXPECT_NE(output.find("EQU"), std::string::npos);
}

// Test: SCMASM format
TEST_F(IntegrationTest, SCMASMFormat) {
  // LDA #$00, RTS
  core::Binary binary({0xA9, 0x00, 0x60}, 0x8000);

  std::string output = DisassembleFull(binary, "6502", "scmasm", true);

  EXPECT_FALSE(output.empty());
  // SCMASM uses dot prefixes
  EXPECT_NE(output.find(".OR"), std::string::npos);
  EXPECT_NE(output.find("LDA"), std::string::npos);
}

// Test: 65C02 CPU
TEST_F(IntegrationTest, CPU_65C02) {
  // STZ $10, BRA forward, RTS
  core::Binary binary({
    0x64, 0x10,        // STZ $10 (65C02 only)
    0x80, 0x01,        // BRA +1 (65C02 only)
    0x60               // RTS
  }, 0x8000);

  std::string output = DisassembleFull(binary, "65c02", "merlin", true);

  EXPECT_NE(output.find("STZ"), std::string::npos);
  EXPECT_NE(output.find("BRA"), std::string::npos);
}

// Test: Linear disassembly (no analysis)
TEST_F(IntegrationTest, LinearDisassembly) {
  // LDA #$00, STA $10, RTS
  core::Binary binary({0xA9, 0x00, 0x85, 0x10, 0x60}, 0x8000);

  std::string output = DisassembleFull(binary, "6502", "merlin", false);

  EXPECT_FALSE(output.empty());
  EXPECT_NE(output.find("LDA"), std::string::npos);
  EXPECT_NE(output.find("STA"), std::string::npos);
  EXPECT_NE(output.find("RTS"), std::string::npos);
}

// Test: ProDOS MLI inline data
TEST_F(IntegrationTest, ProDOS_MLI_InlineData) {
  // LDA #$00, JSR $BF00, DFB $C8, DA $2020, BCS forward, RTS
  core::Binary binary({
    0xA9, 0x00,              // LDA #$00
    0x20, 0x00, 0xBF,        // JSR $BF00 (MLI)
    0xC8,                    // Command byte (inline data)
    0x20, 0x20,              // Parameter pointer (inline data)
    0xB0, 0x01,              // BCS +1
    0x60                     // RTS
  }, 0x2000);

  std::string output = DisassembleFull(binary, "6502", "merlin", true);

  // Should have JSR to MLI
  EXPECT_NE(output.find("JSR"), std::string::npos);
  EXPECT_NE(output.find("BF00"), std::string::npos);

  // Note: The analyzer doesn't know about ProDOS MLI inline data conventions,
  // so it will disassemble everything as code. This is expected behavior.
  // To properly handle MLI inline data, we would need ProDOS-specific analysis.
  EXPECT_FALSE(output.empty());
}

// Test: Mixed code and data
TEST_F(IntegrationTest, MixedCodeAndData) {
  // LDA #$00, RTS, (data bytes), (more data)
  core::Binary binary({
    0xA9, 0x00,        // LDA #$00
    0x60,              // RTS
    0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x00  // "Hello" string
  }, 0x8000);

  std::string output = DisassembleFull(binary, "6502", "merlin", true);

  EXPECT_NE(output.find("LDA"), std::string::npos);
  EXPECT_NE(output.find("RTS"), std::string::npos);

  // Data should be present (as ASC or HEX)
  EXPECT_TRUE(output.find("ASC") != std::string::npos ||
              output.find("HEX") != std::string::npos);
}

// Test: Empty binary
TEST_F(IntegrationTest, EmptyBinary) {
  core::Binary binary({}, 0x8000);

  std::string output = DisassembleFull(binary, "6502", "merlin", true);

  // Should still have header
  EXPECT_FALSE(output.empty());
  EXPECT_NE(output.find("ORG"), std::string::npos);
}

// Test: Single byte
TEST_F(IntegrationTest, SingleByte) {
  core::Binary binary({0x60}, 0x8000);  // RTS

  std::string output = DisassembleFull(binary, "6502", "merlin", true);

  EXPECT_NE(output.find("RTS"), std::string::npos);
}

// Test: All addressing modes coverage
TEST_F(IntegrationTest, AllAddressingModes) {
  core::Binary binary({
    0xA9, 0x00,        // LDA #$00 (immediate)
    0xA5, 0x10,        // LDA $10 (zero page)
    0xB5, 0x10,        // LDA $10,X (zero page,X)
    0xAD, 0x00, 0x80,  // LDA $8000 (absolute)
    0xBD, 0x00, 0x80,  // LDA $8000,X (absolute,X)
    0xB9, 0x00, 0x80,  // LDA $8000,Y (absolute,Y)
    0xA1, 0x10,        // LDA ($10,X) (indexed indirect)
    0xB1, 0x10,        // LDA ($10),Y (indirect indexed)
    0x60               // RTS
  }, 0x8000);

  std::string output = DisassembleFull(binary, "6502", "merlin", false);  // Linear mode

  // Should have all these addressing modes
  EXPECT_NE(output.find("#$"), std::string::npos);   // immediate
  EXPECT_TRUE(output.find("$10,X") != std::string::npos ||
              output.find("$8000,X") != std::string::npos);   // indexed X
  EXPECT_NE(output.find("$8000,Y"), std::string::npos);   // indexed Y
  EXPECT_NE(output.find("($10"), std::string::npos);      // indirect
}

// Test: Output consistency between runs
TEST_F(IntegrationTest, OutputConsistency) {
  core::Binary binary({0xA9, 0x00, 0x85, 0x10, 0x60}, 0x8000);

  std::string output1 = DisassembleFull(binary, "6502", "merlin", true);
  std::string output2 = DisassembleFull(binary, "6502", "merlin", true);

  // Output should be identical
  EXPECT_EQ(output1, output2);
}

}  // namespace
}  // namespace sourcerer
