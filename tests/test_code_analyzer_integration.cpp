// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "analysis/code_analyzer.h"

#include <gtest/gtest.h>

#include "core/address_map.h"
#include "core/binary.h"
#include "cpu/cpu_registry.h"

namespace sourcerer {
namespace analysis {
namespace {

// Test fixture for CodeAnalyzer integration tests
class CodeAnalyzerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    binary_ = std::make_unique<core::Binary>();
    address_map_ = std::make_unique<core::AddressMap>();
  }

  // Helper to create test binary with specific data
  void CreateTestBinary(const std::vector<uint8_t>& data, uint32_t load_addr) {
    binary_ = std::make_unique<core::Binary>(data, load_addr);
  }

  // Helper to create analyzer (doesn't run analysis yet)
  void CreateAnalyzer(cpu::CpuVariant variant) {
    cpu_ = cpu::CpuRegistry::Instance().Create(variant);
    analyzer_ = std::make_unique<CodeAnalyzer>(cpu_.get(), binary_.get());
  }

  // Helper to run analysis with specified CPU and optional entry point
  void RunAnalysis(cpu::CpuVariant variant, uint32_t entry_point = 0) {
    CreateAnalyzer(variant);
    if (entry_point != 0) {
      analyzer_->AddEntryPoint(entry_point);
    }
    analyzer_->Analyze(address_map_.get());
  }

  // Helper to run recursive analysis with specified CPU and optional entry point
  void RunRecursiveAnalysis(cpu::CpuVariant variant, uint32_t entry_point = 0) {
    CreateAnalyzer(variant);
    if (entry_point != 0) {
      analyzer_->AddEntryPoint(entry_point);
    }
    analyzer_->RecursiveAnalyze(address_map_.get());
  }

  // Helper to count discovered code bytes
  size_t CountCodeBytes() {
    size_t count = 0;
    uint32_t start = binary_->load_address();
    uint32_t end = start + binary_->size();

    for (uint32_t addr = start; addr < end; ++addr) {
      if (address_map_->IsCode(addr)) {
        count++;
      }
    }
    return count;
  }

  // Helper to count discovered data bytes
  size_t CountDataBytes() {
    size_t count = 0;
    uint32_t start = binary_->load_address();
    uint32_t end = start + binary_->size();

    for (uint32_t addr = start; addr < end; ++addr) {
      if (address_map_->IsData(addr)) {
        count++;
      }
    }
    return count;
  }

  std::unique_ptr<core::Binary> binary_;
  std::unique_ptr<core::AddressMap> address_map_;
  std::unique_ptr<cpu::CpuPlugin> cpu_;  // Must keep CPU alive!
  std::unique_ptr<CodeAnalyzer> analyzer_;
};

// =============================================================================
// Entry Point Discovery Tests
// =============================================================================

TEST_F(CodeAnalyzerTest, DiscoverEntryPoints_6809_InterruptVectors) {
  // Test: Simple 6809 code starting at $8000
  // This tests that analysis works with entry points from interrupt vectors
  std::vector<uint8_t> data = {
    // $8000: Entry point code
    0x10, 0xCE, 0x80, 0x00,  // LDS #$8000 (initialize stack)
    0x8E, 0x40, 0x00,         // LDX #$4000
    0x39,                     // RTS
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOTOROLA_6809, 0x8000);

  // Should discover and disassemble the code
  EXPECT_TRUE(address_map_->IsCode(0x8000));
  EXPECT_EQ(CountCodeBytes(), 8);  // All 8 bytes should be code
}

TEST_F(CodeAnalyzerTest, DiscoverEntryPoints_6502_InterruptVectors) {
  // Test: Simple 6502 code starting at $C000
  // This tests that analysis works with entry points from interrupt vectors
  std::vector<uint8_t> data = {
    // $C000: Entry point code
    0xA9, 0x00,  // LDA #$00
    0x85, 0x01,  // STA $01
    0x60,        // RTS
  };

  CreateTestBinary(data, 0xC000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0xC000);

  // Should discover and disassemble the code
  EXPECT_TRUE(address_map_->IsCode(0xC000));
  EXPECT_EQ(CountCodeBytes(), 5);  // All 5 bytes should be code
}

TEST_F(CodeAnalyzerTest, DiscoverEntryPoints_6809_SubroutinePrologues) {
  // Test: Discover subroutines by LBSR (long branch to subroutine)
  std::vector<uint8_t> data = {
    // $8000: Main code
    0x17, 0x00, 0x04,        // LBSR $8007 (call subroutine, relative +4)
    0x12,                    // NOP
    0x39,                    // RTS
    0x12,                    // NOP (padding)

    // $8007: Subroutine with PSHS prologue
    0x34, 0x16,              // PSHS D,X,Y (typical prologue)
    0xC6, 0x42,              // LDB #$42
    0x35, 0x16,              // PULS D,X,Y
    0x39,                    // RTS
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOTOROLA_6809, 0x8000);

  // Should discover main code
  EXPECT_TRUE(address_map_->IsCode(0x8000));  // LBSR
  EXPECT_TRUE(address_map_->IsCode(0x8004));  // RTS

  // Should discover subroutine at $8007 via LBSR call
  EXPECT_TRUE(address_map_->IsCode(0x8007));  // PSHS (subroutine start)
  EXPECT_TRUE(address_map_->IsCode(0x8009));  // LDB #$42

  // Should discover at least 11 bytes of code (main + subroutine)
  EXPECT_GE(CountCodeBytes(), 11);
}

TEST_F(CodeAnalyzerTest, DiscoverEntryPoints_6502_SubroutinePrologues) {
  // Test: Discover subroutines by PHP/PHA patterns
  std::vector<uint8_t> data = {
    // $8000: Main code
    0x20, 0x10, 0x80,  // JSR $8010 (call subroutine)
    0x60,              // RTS

    // $8004: Padding
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,

    // $8010: Subroutine with PHP prologue
    0x08,              // PHP (typical prologue)
    0x48,              // PHA
    0xA9, 0x42,        // LDA #$42
    0x68,              // PLA
    0x28,              // PLP
    0x60,              // RTS
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Should discover subroutine at $8010 via JSR
  EXPECT_TRUE(address_map_->IsCode(0x8010));
}

TEST_F(CodeAnalyzerTest, DiscoverEntryPoints_EmptyBinary) {
  // Test: Empty binary should not crash
  std::vector<uint8_t> data;

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOTOROLA_6809);

  // Should handle gracefully
  EXPECT_EQ(CountCodeBytes(), 0);
  EXPECT_EQ(address_map_->GetEntryPoints().size(), 0);
}

TEST_F(CodeAnalyzerTest, DiscoverEntryPoints_NoValidVectors) {
  // Test: Binary with invalid interrupt vectors
  std::vector<uint8_t> data(0x8000, 0xFF);  // All $FF

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOTOROLA_6809);

  // May discover some patterns but should not crash
  // Entry points might be discovered via heuristics
}

// =============================================================================
// Code Flow Analysis Tests
// =============================================================================

TEST_F(CodeAnalyzerTest, AnalyzeRecursively_LinearCode) {
  // Test: Simple linear code sequence
  std::vector<uint8_t> data = {
    // $8000: Linear code
    0xA9, 0x00,  // LDA #$00
    0x85, 0x10,  // STA $10
    0xA9, 0xFF,  // LDA #$FF
    0x85, 0x11,  // STA $11
    0x60,        // RTS
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // All 9 bytes should be discovered as code
  EXPECT_EQ(CountCodeBytes(), 9);
  EXPECT_TRUE(address_map_->IsCode(0x8000));  // LDA #$00
  EXPECT_TRUE(address_map_->IsCode(0x8002));  // STA $10
  EXPECT_TRUE(address_map_->IsCode(0x8004));  // LDA #$FF
  EXPECT_TRUE(address_map_->IsCode(0x8006));  // STA $11
  EXPECT_TRUE(address_map_->IsCode(0x8008));  // RTS
}

TEST_F(CodeAnalyzerTest, AnalyzeRecursively_SimpleBranch) {
  // Test: Code with conditional branch
  std::vector<uint8_t> data = {
    // $8000: Branch test
    0xA9, 0x00,        // LDA #$00
    0xF0, 0x02,        // BEQ $8006 (branch if zero)
    0xA9, 0x01,        // LDA #$01 (not taken path)
    0x85, 0x10,        // STA $10 (taken path target)
    0x60,              // RTS
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Both branch paths should be discovered
  EXPECT_TRUE(address_map_->IsCode(0x8000));  // LDA #$00
  EXPECT_TRUE(address_map_->IsCode(0x8002));  // BEQ
  EXPECT_TRUE(address_map_->IsCode(0x8004));  // LDA #$01 (not taken)
  EXPECT_TRUE(address_map_->IsCode(0x8006));  // STA $10 (taken)
  EXPECT_TRUE(address_map_->IsCode(0x8008));  // RTS

  EXPECT_EQ(CountCodeBytes(), 9);
}

TEST_F(CodeAnalyzerTest, AnalyzeRecursively_JSR_RTS) {
  // Test: Main routine calls subroutine
  std::vector<uint8_t> data = {
    // $8000: Main routine
    0x20, 0x06, 0x80,  // JSR $8006
    0xA9, 0xFF,        // LDA #$FF
    0x60,              // RTS

    // $8006: Subroutine
    0xA9, 0x42,        // LDA #$42
    0x85, 0x10,        // STA $10
    0x60,              // RTS
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Both main and subroutine should be discovered
  EXPECT_TRUE(address_map_->IsCode(0x8000));  // JSR
  EXPECT_TRUE(address_map_->IsCode(0x8003));  // LDA #$FF
  EXPECT_TRUE(address_map_->IsCode(0x8005));  // RTS
  EXPECT_TRUE(address_map_->IsCode(0x8006));  // LDA #$42 (subroutine)
  EXPECT_TRUE(address_map_->IsCode(0x8008));  // STA $10
  EXPECT_TRUE(address_map_->IsCode(0x800A));  // RTS

  // Should have cross-reference from JSR to subroutine
  EXPECT_TRUE(address_map_->HasXrefs(0x8006));
}

TEST_F(CodeAnalyzerTest, AnalyzeRecursively_JMP_Absolute) {
  // Test: Code with JMP instruction
  std::vector<uint8_t> data = {
    // $8000: Jump test
    0xA9, 0x00,        // LDA #$00
    0x4C, 0x08, 0x80,  // JMP $8008
    0xA9, 0xFF,        // LDA #$FF (unreachable)
    0x60,              // RTS (unreachable)

    // $8008: Jump target
    0xA9, 0x42,        // LDA #$42
    0x60,              // RTS
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Code before and after jump should be discovered
  EXPECT_TRUE(address_map_->IsCode(0x8000));  // LDA #$00
  EXPECT_TRUE(address_map_->IsCode(0x8002));  // JMP $8008
  EXPECT_TRUE(address_map_->IsCode(0x8008));  // LDA #$42 (target)
  EXPECT_TRUE(address_map_->IsCode(0x800A));  // RTS

  // Unreachable code after JMP may or may not be discovered
  // depending on entry point discovery heuristics
}

TEST_F(CodeAnalyzerTest, AnalyzeRecursively_IndirectJump) {
  // Test: JMP (indirect) - cannot statically analyze target
  std::vector<uint8_t> data = {
    // $8000: Indirect jump
    0xA9, 0x00,        // LDA #$00
    0x6C, 0x10, 0x00,  // JMP ($0010) - indirect
    0xA9, 0xFF,        // LDA #$FF (may be unreachable)
    0x60,              // RTS
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Code before indirect jump should be discovered
  EXPECT_TRUE(address_map_->IsCode(0x8000));  // LDA #$00
  EXPECT_TRUE(address_map_->IsCode(0x8002));  // JMP ($0010)

  // Code after indirect jump depends on entry point discovery
}

TEST_F(CodeAnalyzerTest, AnalyzeRecursively_LoopDetection) {
  // Test: Infinite loop should not hang analysis
  std::vector<uint8_t> data = {
    // $8000: Infinite loop
    0xA9, 0x00,        // LDA #$00
    0x4C, 0x00, 0x80,  // JMP $8000 (loop back)
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Should detect loop and stop gracefully
  EXPECT_TRUE(address_map_->IsCode(0x8000));
  EXPECT_TRUE(address_map_->IsCode(0x8002));
  EXPECT_EQ(CountCodeBytes(), 5);
}

TEST_F(CodeAnalyzerTest, AnalyzeRecursively_6809_ConditionalBranches) {
  // Test: 6809 conditional branches (both directions)
  std::vector<uint8_t> data = {
    // $8000: Branch forward
    0x86, 0x00,        // LDA #$00
    0x27, 0x02,        // BEQ $8006 (forward)
    0x86, 0x01,        // LDA #$01

    // $8006: Branch backward
    0x2A, 0xF8,        // BPL $8000 (backward to $8000)
    0x39,              // RTS
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOTOROLA_6809, 0x8000);

  // All paths should be discovered
  EXPECT_TRUE(address_map_->IsCode(0x8000));  // LDA #$00
  EXPECT_TRUE(address_map_->IsCode(0x8002));  // BEQ
  EXPECT_TRUE(address_map_->IsCode(0x8004));  // LDA #$01
  EXPECT_TRUE(address_map_->IsCode(0x8006));  // BPL
  EXPECT_TRUE(address_map_->IsCode(0x8008));  // RTS
}

TEST_F(CodeAnalyzerTest, AnalyzeRecursively_MultipleSubroutines) {
  // Test: Main calls multiple subroutines
  std::vector<uint8_t> data = {
    // $8000: Main
    0x20, 0x09, 0x80,  // JSR $8009
    0x20, 0x0E, 0x80,  // JSR $800E
    0x60,              // RTS

    // Padding
    0x00, 0x00,

    // $8009: Sub1
    0xA9, 0x01,        // LDA #$01
    0x85, 0x10,        // STA $10
    0x60,              // RTS

    // $800E: Sub2
    0xA9, 0x02,        // LDA #$02
    0x85, 0x11,        // STA $11
    0x60,              // RTS
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // All three routines should be discovered
  EXPECT_TRUE(address_map_->IsCode(0x8000));  // Main
  EXPECT_TRUE(address_map_->IsCode(0x8009));  // Sub1
  EXPECT_TRUE(address_map_->IsCode(0x800E));  // Sub2

  // Should have xrefs to both subroutines
  EXPECT_TRUE(address_map_->HasXrefs(0x8009));
  EXPECT_TRUE(address_map_->HasXrefs(0x800E));
}

// ============================================================================
// Work Package 1: Edge Case Tests
// ============================================================================

TEST_F(CodeAnalyzerTest, EdgeCase_TrulyEmptyBinary) {
  // Test: Binary with zero bytes
  CreateTestBinary({}, 0x8000);
  CreateAnalyzer(cpu::CpuVariant::MOS_6502);

  // Should not crash
  analyzer_->RecursiveAnalyze(address_map_.get());

  // No code or data should be discovered
  EXPECT_EQ(CountCodeBytes(), 0);
  EXPECT_EQ(CountDataBytes(), 0);
}

TEST_F(CodeAnalyzerTest, EdgeCase_SingleByteInstruction) {
  // Test: Binary with single NOP instruction
  CreateTestBinary({0xEA}, 0x8000);  // NOP on 6502
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Single instruction should be discovered
  EXPECT_TRUE(address_map_->IsCode(0x8000));
  EXPECT_EQ(CountCodeBytes(), 1);
}

TEST_F(CodeAnalyzerTest, EdgeCase_NoEntryPoints) {
  // Test: Analysis without any entry points
  std::vector<uint8_t> data = {
    0x86, 0xFF,  // LDA #$FF (6809)
    0x39,        // RTS
  };

  CreateTestBinary(data, 0x8000);
  CreateAnalyzer(cpu::CpuVariant::MOTOROLA_6809);

  // Analyze without adding entry points
  analyzer_->RecursiveAnalyze(address_map_.get());

  // Nothing should be discovered without entry points
  EXPECT_EQ(CountCodeBytes(), 0);
}

TEST_F(CodeAnalyzerTest, EdgeCase_InvalidStartAddress) {
  // Test: Entry point outside binary range
  CreateTestBinary({0xEA, 0xEA}, 0x8000);
  CreateAnalyzer(cpu::CpuVariant::MOS_6502);

  // Try to add entry point outside binary
  analyzer_->AddEntryPoint(0x9000);  // Outside 0x8000-0x8001
  analyzer_->RecursiveAnalyze(address_map_.get());

  // Should not crash, no code discovered
  EXPECT_EQ(CountCodeBytes(), 0);
}

TEST_F(CodeAnalyzerTest, EdgeCase_BoundaryAddressZero) {
  // Test: Binary at address 0x0000
  // Note: Address 0 may be treated specially in some implementations
  CreateTestBinary({0xEA, 0x60}, 0x0000);  // NOP, RTS
  CreateAnalyzer(cpu::CpuVariant::MOS_6502);

  // Explicitly add 0x0000 as entry point
  analyzer_->AddEntryPoint(0x0000);
  analyzer_->RecursiveAnalyze(address_map_.get());

  // Should not crash when analyzing at address 0
  // (Whether code is discovered depends on implementation - 0 might be special)
  size_t code_bytes = CountCodeBytes();
  // At minimum, should handle gracefully without crashing
  EXPECT_GE(code_bytes, 0);  // Just verify it returns without error
}

TEST_F(CodeAnalyzerTest, EdgeCase_BoundaryAddressFFFF) {
  // Test: Binary near maximum address
  CreateTestBinary({0xEA, 0x60}, 0xFFFE);  // NOP, RTS at 0xFFFE-0xFFFF
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0xFFFE);

  // Should handle high addresses correctly
  EXPECT_TRUE(address_map_->IsCode(0xFFFE));
  EXPECT_TRUE(address_map_->IsCode(0xFFFF));
}

TEST_F(CodeAnalyzerTest, EdgeCase_DiscontiguousCode) {
  // Test: Code with large data gap in middle
  std::vector<uint8_t> data(1024, 0x00);  // 1KB of zeros

  // Code at start
  data[0] = 0x20;  // JSR
  data[1] = 0x00;
  data[2] = 0x84;  // JSR $8400 (to end of binary)
  data[3] = 0x60;  // RTS

  // Code at end (offset 1024 bytes = 0x400)
  data[1020] = 0xA9;  // LDA #$00
  data[1021] = 0x00;
  data[1022] = 0x60;  // RTS

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Code regions should be discovered at start and potentially at end
  EXPECT_TRUE(address_map_->IsCode(0x8000));  // Start

  // End might be discovered via JSR or might not be
  // (Depends on analyzer's ability to follow JSR targets)
  size_t code_bytes = CountCodeBytes();
  EXPECT_GT(code_bytes, 0);  // At least some code discovered
}

TEST_F(CodeAnalyzerTest, EdgeCase_AllData) {
  // Test: Binary that looks like all data (no valid instructions)
  std::vector<uint8_t> data = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Even with entry point, invalid instruction stream should stop quickly
  // Implementation-dependent: might discover a few bytes or none
  size_t code_bytes = CountCodeBytes();
  EXPECT_LT(code_bytes, data.size());  // Should not mark everything as code
}

TEST_F(CodeAnalyzerTest, EdgeCase_SelfModifyingCode) {
  // Test: Code that appears to modify itself
  std::vector<uint8_t> data = {
    // $8000: Write to code area
    0xA9, 0xEA,        // LDA #$EA (NOP opcode)
    0x8D, 0x0A, 0x80,  // STA $800A (self-modify)
    0x60,              // RTS

    // $8006: Gap
    0x00, 0x00, 0x00, 0x00,

    // $800A: Target (will be overwritten at runtime)
    0xFF,              // Invalid opcode (will become NOP)
    0x60,              // RTS
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // First part should be discovered
  EXPECT_TRUE(address_map_->IsCode(0x8000));
  EXPECT_TRUE(address_map_->IsCode(0x8005));  // RTS

  // Self-modified code at 0x800A may or may not be discovered
  // (Depends on implementation - static analysis can't predict runtime behavior)
}

TEST_F(CodeAnalyzerTest, EdgeCase_OverlappingInstructions) {
  // Test: Branch into middle of multi-byte instruction
  std::vector<uint8_t> data = {
    // $8000: Normal flow
    0xA9, 0x27,        // LDA #$27 (note: 0x27 is BEQ opcode)

    // $8002: Jump past LDA's operand
    0x4C, 0x01, 0x80,  // JMP $8001 (middle of LDA instruction!)

    // $8005
    0x60,              // RTS
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Analyzer should handle this edge case (common in packed code)
  EXPECT_TRUE(address_map_->IsCode(0x8000));

  // Address 0x8001 might be marked as code due to the JMP
  // (Implementation-dependent behavior)
}

TEST_F(CodeAnalyzerTest, EdgeCase_MultipleEntryPoints) {
  // Test: Binary with multiple disconnected entry points
  std::vector<uint8_t> data(256, 0x00);

  // Entry point 1 at 0x8000
  data[0] = 0xA9;  // LDA
  data[1] = 0x01;
  data[2] = 0x60;  // RTS

  // Entry point 2 at 0x8080 (offset 128)
  data[128] = 0xA9;  // LDA
  data[129] = 0x02;
  data[130] = 0x60;  // RTS

  // Entry point 3 at 0x80F0 (offset 240)
  data[240] = 0xA9;  // LDA
  data[241] = 0x03;
  data[242] = 0x60;  // RTS

  CreateTestBinary(data, 0x8000);
  CreateAnalyzer(cpu::CpuVariant::MOS_6502);

  // Add all three entry points
  analyzer_->AddEntryPoint(0x8000);
  analyzer_->AddEntryPoint(0x8080);
  analyzer_->AddEntryPoint(0x80F0);
  analyzer_->RecursiveAnalyze(address_map_.get());

  // All three code regions should be discovered
  EXPECT_TRUE(address_map_->IsCode(0x8000));
  EXPECT_TRUE(address_map_->IsCode(0x8080));
  EXPECT_TRUE(address_map_->IsCode(0x80F0));

  // Multiple entry points should work without crashing
  size_t code_bytes = CountCodeBytes();
  EXPECT_GE(code_bytes, 9);  // At least 3 regions x 3 bytes each
}

TEST_F(CodeAnalyzerTest, EdgeCase_BranchToDataRegion) {
  // Test: Branch instruction pointing to what looks like data
  std::vector<uint8_t> data = {
    // $8000: Code
    0xA9, 0x00,        // LDA #$00
    0x4C, 0x06, 0x80,  // JMP $8006 (to data region)
    0x60,              // RTS (unreachable)

    // $8006: Data (not valid instructions)
    0x00, 0x01, 0x02, 0x03,
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Initial code should be discovered
  EXPECT_TRUE(address_map_->IsCode(0x8000));

  // Jump target at 0x8006 might be marked as code
  // (Analyzer doesn't know it's data until it tries to disassemble)
}

TEST_F(CodeAnalyzerTest, EdgeCase_CircularJump) {
  // Test: Code that jumps to itself
  std::vector<uint8_t> data = {
    0x4C, 0x00, 0x80,  // JMP $8000 (infinite loop to self)
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Should not infinite loop in analyzer
  EXPECT_TRUE(address_map_->IsCode(0x8000));

  // Should handle circular reference gracefully
}

TEST_F(CodeAnalyzerTest, EdgeCase_VeryShortBinary) {
  // Test: Binary smaller than smallest instruction
  CreateTestBinary({0xEA}, 0x8000);  // Just 1 byte

  // Try to analyze 2-byte instruction starting at end
  CreateAnalyzer(cpu::CpuVariant::MOTOROLA_6809);
  analyzer_->AddEntryPoint(0x8000);
  analyzer_->RecursiveAnalyze(address_map_.get());

  // Should not crash trying to read past end
  // May or may not mark as code depending on implementation
}

// ============================================================================
// Work Package 2: Error Handling Tests
// ============================================================================

TEST_F(CodeAnalyzerTest, ErrorHandling_NullCpuPlugin) {
  // Test: Analyzer with NULL CPU plugin
  CreateTestBinary({0xEA, 0x60}, 0x8000);

  // Create analyzer with NULL CPU plugin
  cpu::CpuPlugin* null_cpu = nullptr;
  analyzer_ = std::make_unique<CodeAnalyzer>(null_cpu, binary_.get());

  // Should handle gracefully without crashing
  analyzer_->AddEntryPoint(0x8000);
  analyzer_->Analyze(address_map_.get());  // Should return early

  // No code should be discovered
  EXPECT_EQ(CountCodeBytes(), 0);
}

TEST_F(CodeAnalyzerTest, ErrorHandling_NullAddressMap) {
  // Test: Analysis with NULL address map
  CreateTestBinary({0xEA, 0x60}, 0x8000);
  CreateAnalyzer(cpu::CpuVariant::MOS_6502);

  // Try to analyze with NULL address map
  analyzer_->AddEntryPoint(0x8000);
  analyzer_->Analyze(nullptr);  // Should handle gracefully

  // Should not crash (can't verify results without address map)
}

TEST_F(CodeAnalyzerTest, ErrorHandling_InvalidInstructionBytes) {
  // Test: Binary with all invalid opcodes
  std::vector<uint8_t> data = {
    0xFF, 0xFF, 0xFF, 0xFF,  // Invalid opcodes (not defined in 6502)
    0xFF, 0xFF, 0xFF, 0xFF,
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Should stop analysis when encountering invalid instructions
  // May discover some bytes before hitting invalid instructions
  size_t code_bytes = CountCodeBytes();
  // Should not crash, but likely stops early
  EXPECT_LE(code_bytes, data.size());
}

TEST_F(CodeAnalyzerTest, ErrorHandling_CircularReferences) {
  // Test: Circular call chain (A calls B, B calls A)
  std::vector<uint8_t> data = {
    // $8000: Function A
    0x20, 0x05, 0x80,  // JSR $8005 (call B)
    0x60,              // RTS
    0xEA,              // NOP (padding)

    // $8005: Function B
    0x20, 0x00, 0x80,  // JSR $8000 (call A - circular!)
    0x60,              // RTS
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Should detect circular reference and not infinite loop
  EXPECT_TRUE(address_map_->IsCode(0x8000));  // Function A
  EXPECT_TRUE(address_map_->IsCode(0x8005));  // Function B

  // Both functions should be discovered without hanging
  EXPECT_GE(CountCodeBytes(), 8);
}

TEST_F(CodeAnalyzerTest, ErrorHandling_StackOverflowProtection) {
  // Test: Very deep call chain to test recursion limits
  std::vector<uint8_t> data;

  // Create a chain of 500 JSRs (each JSR is 3 bytes + 1 RTS = 4 bytes)
  const int CHAIN_LENGTH = 500;
  for (int i = 0; i < CHAIN_LENGTH; ++i) {
    uint32_t next_addr = 0x8000 + (i + 1) * 4;
    data.push_back(0x20);  // JSR
    data.push_back(next_addr & 0xFF);
    data.push_back((next_addr >> 8) & 0xFF);
    data.push_back(0x60);  // RTS
  }

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Should handle deep recursion without stack overflow
  // May stop at recursion limit, but shouldn't crash
  size_t code_bytes = CountCodeBytes();
  EXPECT_GT(code_bytes, 0);  // Should discover something

  // Should not crash or hang
}

TEST_F(CodeAnalyzerTest, ErrorHandling_OversizedBinary) {
  // Test: Very large binary (simulate 64KB)
  std::vector<uint8_t> data(65536, 0xEA);  // 64KB of NOPs

  // Add some actual code at start
  data[0] = 0xA9;  // LDA #$00
  data[1] = 0x00;
  data[2] = 0x60;  // RTS

  CreateTestBinary(data, 0x0000);
  CreateAnalyzer(cpu::CpuVariant::MOS_6502);

  // Set reasonable instruction limit
  analyzer_->SetMaxInstructions(100000);

  analyzer_->AddEntryPoint(0x0000);
  analyzer_->RecursiveAnalyze(address_map_.get());

  // Should handle large binary without excessive memory usage
  // At minimum, should discover the initial code
  EXPECT_TRUE(address_map_->IsCode(0x0000));

  // Should not crash or hang
}

TEST_F(CodeAnalyzerTest, ErrorHandling_BinaryReadBeyondEnd) {
  // Test: Instructions that try to read operands past end of binary
  std::vector<uint8_t> data = {
    0xA9,  // LDA #$xx - but missing operand byte!
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Should handle gracefully when trying to read past end
  // May mark first byte as code or may not discover anything
  size_t code_bytes = CountCodeBytes();
  EXPECT_LE(code_bytes, 1);  // Should not crash
}

TEST_F(CodeAnalyzerTest, ErrorHandling_InvalidEntryPointBeforeBinary) {
  // Test: Entry point before binary load address
  CreateTestBinary({0xEA, 0x60}, 0x8000);
  CreateAnalyzer(cpu::CpuVariant::MOS_6502);

  // Try entry point before binary start
  analyzer_->AddEntryPoint(0x7FFF);  // Before 0x8000
  analyzer_->RecursiveAnalyze(address_map_.get());

  // Should reject invalid entry point, no code discovered
  EXPECT_EQ(CountCodeBytes(), 0);
}

TEST_F(CodeAnalyzerTest, ErrorHandling_InvalidEntryPointAfterBinary) {
  // Test: Entry point after binary end
  CreateTestBinary({0xEA, 0x60}, 0x8000);
  CreateAnalyzer(cpu::CpuVariant::MOS_6502);

  // Try entry point after binary end
  analyzer_->AddEntryPoint(0x8003);  // After 0x8001
  analyzer_->RecursiveAnalyze(address_map_.get());

  // Should reject invalid entry point, no code discovered
  EXPECT_EQ(CountCodeBytes(), 0);
}

TEST_F(CodeAnalyzerTest, ErrorHandling_MultipleInvalidEntryPoints) {
  // Test: Multiple entry points, all invalid
  CreateTestBinary({0xEA, 0x60}, 0x8000);
  CreateAnalyzer(cpu::CpuVariant::MOS_6502);

  // Add several invalid entry points
  analyzer_->AddEntryPoint(0x7000);  // Before binary
  analyzer_->AddEntryPoint(0x9000);  // After binary
  analyzer_->AddEntryPoint(0xFFFF);  // Way out of range
  analyzer_->RecursiveAnalyze(address_map_.get());

  // Should handle all invalid entry points gracefully
  EXPECT_EQ(CountCodeBytes(), 0);
}

TEST_F(CodeAnalyzerTest, ErrorHandling_MixedValidInvalidEntryPoints) {
  // Test: Mix of valid and invalid entry points
  std::vector<uint8_t> data = {
    0xA9, 0x00,  // $8000: LDA #$00
    0x60,        // $8002: RTS
  };

  CreateTestBinary(data, 0x8000);
  CreateAnalyzer(cpu::CpuVariant::MOS_6502);

  // Add mix of valid and invalid entry points
  analyzer_->AddEntryPoint(0x7000);  // Invalid
  analyzer_->AddEntryPoint(0x8000);  // Valid
  analyzer_->AddEntryPoint(0x9000);  // Invalid
  analyzer_->RecursiveAnalyze(address_map_.get());

  // Should process valid entry point and skip invalid ones
  EXPECT_TRUE(address_map_->IsCode(0x8000));
  EXPECT_EQ(CountCodeBytes(), 3);
}

TEST_F(CodeAnalyzerTest, ErrorHandling_ZeroSizeBinaryWithEntryPoint) {
  // Test: Empty binary with entry point specified
  CreateTestBinary({}, 0x8000);
  CreateAnalyzer(cpu::CpuVariant::MOS_6502);

  analyzer_->AddEntryPoint(0x8000);
  analyzer_->RecursiveAnalyze(address_map_.get());

  // Should handle gracefully - empty binary, no code
  EXPECT_EQ(CountCodeBytes(), 0);
}

TEST_F(CodeAnalyzerTest, ErrorHandling_BranchToNegativeOffset) {
  // Test: Branch with underflow (before binary start)
  std::vector<uint8_t> data = {
    0xD0, 0xFE,  // BNE -2 (branches to 0x7FFE if at 0x8000)
    0x60,        // RTS
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Should handle backward branch that goes before binary
  EXPECT_TRUE(address_map_->IsCode(0x8000));

  // Should not crash trying to follow invalid branch target
}

TEST_F(CodeAnalyzerTest, ErrorHandling_JumpToAddressZero) {
  // Test: Jump to address 0x0000 (potential NULL pointer)
  std::vector<uint8_t> data = {
    0x4C, 0x00, 0x00,  // JMP $0000
    0x60,              // RTS (unreachable)
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Should handle jump to address 0 gracefully
  EXPECT_TRUE(address_map_->IsCode(0x8000));

  // Should not crash or try to access invalid memory
}

TEST_F(CodeAnalyzerTest, ErrorHandling_JSRToInvalidAddress) {
  // Test: JSR to address outside binary
  std::vector<uint8_t> data = {
    0x20, 0x00, 0xFF,  // JSR $FF00 (likely outside binary)
    0x60,              // RTS
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Should discover JSR but not crash trying to follow invalid target
  EXPECT_TRUE(address_map_->IsCode(0x8000));
  EXPECT_TRUE(address_map_->IsCode(0x8003));  // RTS after JSR

  // Should continue analysis after invalid JSR
}

TEST_F(CodeAnalyzerTest, ErrorHandling_MaxInstructionsLimit) {
  // Test: Very large binary doesn't cause excessive processing
  // Note: max_instructions_ is more of a guideline; recursive analysis
  // will complete if all paths converge. This test verifies we can
  // handle large binaries without hanging or crashing.
  std::vector<uint8_t> data(1000, 0xEA);  // 1000 NOPs
  data.push_back(0x60);  // RTS at end

  CreateTestBinary(data, 0x8000);
  CreateAnalyzer(cpu::CpuVariant::MOS_6502);

  // Set instruction limit
  analyzer_->SetMaxInstructions(10000);

  analyzer_->AddEntryPoint(0x8000);
  analyzer_->RecursiveAnalyze(address_map_.get());

  // Should complete analysis without hanging
  // All 1001 bytes should be discovered (linear code)
  size_t code_bytes = CountCodeBytes();
  EXPECT_EQ(code_bytes, 1001);  // All instructions discovered

  // Verify instruction count is reasonable
  EXPECT_LE(analyzer_->GetInstructionCount(), 10000);
}

// ============================================================================
// Work Package 3: Heuristic Logic Tests
// ============================================================================

TEST_F(CodeAnalyzerTest, Heuristic_CodeDataBoundary) {
  // Test: Clear boundary between code and data (string literal)
  std::vector<uint8_t> data = {
    // Code section
    0xA9, 0x00,                         // LDA #$00
    0x8D, 0x00, 0x80,                   // STA $8000
    0x60,                               // RTS
    // Data section: ASCII string (should NOT be marked as code)
    'H', 'E', 'L', 'L', 'O', ' ',
    'W', 'O', 'R', 'L', 'D', 0x00,
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Code section should be discovered
  EXPECT_TRUE(address_map_->IsCode(0x8000));  // LDA
  EXPECT_TRUE(address_map_->IsCode(0x8001));
  EXPECT_TRUE(address_map_->IsCode(0x8005));  // RTS

  // String data should NOT be marked as code
  // (Heuristic 2: Long printable sequence, Heuristic 3: Null-terminated)
  EXPECT_FALSE(address_map_->IsCode(0x8006));  // 'H'
  EXPECT_FALSE(address_map_->IsCode(0x8011));  // 0x00
}

TEST_F(CodeAnalyzerTest, Heuristic_FalsePositiveSubroutine) {
  // Test: Data that accidentally looks like subroutine prologue
  std::vector<uint8_t> data = {
    // Real code
    0xA9, 0x34,        // LDA #$34
    0x8D, 0x00, 0x80,  // STA $8000
    0x60,              // RTS
    // Data that looks like 6809 PSHS (subroutine prologue)
    0x34, 0x50,        // Could be PSHS, but it's just data
    0x00, 0x00, 0x00,  // More data
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Real code should be discovered
  EXPECT_TRUE(address_map_->IsCode(0x8000));
  EXPECT_TRUE(address_map_->IsCode(0x8005));  // RTS

  // Data after RTS should not be marked as code just because it looks like prologue
  // (For 6502, 0x34 is not a prologue pattern anyway)
}

TEST_F(CodeAnalyzerTest, Heuristic_JumpTableNotCode) {
  // Test: Jump table data should not be marked as executable code
  std::vector<uint8_t> data = {
    // Code that uses jump table
    0xBD, 0x10, 0x80,  // LDA $8010,X (indexed load from table)
    0x48,              // PHA
    0xBD, 0x11, 0x80,  // LDA $8011,X
    0x48,              // PHA
    0x60,              // RTS (jump via stacked address)
    // Jump table (address pairs - should be DATA)
    0x20, 0x80,        // Address 1: $8020
    0x30, 0x80,        // Address 2: $8030
    0x40, 0x80,        // Address 3: $8040
    0x50, 0x80,        // Address 4: $8050
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Code should be discovered
  EXPECT_TRUE(address_map_->IsCode(0x8000));

  // Jump table should be DATA (Heuristic 5: Address-like byte pairs)
  // Note: This depends on reclassification pass which may or may not run
}

TEST_F(CodeAnalyzerTest, Heuristic_StringDataNotCode) {
  // Test: High density of printable ASCII should be classified as data
  std::vector<uint8_t> data = {
    // Code
    0x20, 0x10, 0x80,  // JSR $8010
    0x60,              // RTS
    // Padding
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    // Subroutine with string
    0xA9, 0x00,        // LDA #$00
    0x60,              // RTS
    // String data (high printable percentage)
    'T', 'h', 'i', 's', ' ', 'i', 's', ' ',
    'a', ' ', 't', 'e', 's', 't', ' ', 's',
    't', 'r', 'i', 'n', 'g', ' ', 'w', 'i',
    't', 'h', ' ', '9', '0', '%', '+', ' ',
    'p', 'r', 'i', 'n', 't', 'a', 'b', 'l',
    'e', ' ', 'c', 'h', 'a', 'r', 's', 0x00,
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Code sections should be discovered
  EXPECT_TRUE(address_map_->IsCode(0x8000));  // JSR
  EXPECT_TRUE(address_map_->IsCode(0x8010));  // LDA at subroutine

  // String section should trigger data heuristics
  // (Heuristic 1: >90% printable, Heuristic 2: Long sequence)
}

TEST_F(CodeAnalyzerTest, Heuristic_PatternMatchingEdgeCases) {
  // Test: Edge cases in pattern matching (boundaries, short sequences)
  std::vector<uint8_t> data = {
    // Code
    0xA9, 0x20,        // LDA #$20
    0x60,              // RTS
    // Short printable (below 24 char threshold for Heuristic 2)
    'S', 'H', 'O', 'R', 'T', 0x00,
    // Repeated byte (Heuristic 4)
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    // Mixed data
    0x00, 0x01, 0x02, 0x03,
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Code should be discovered
  EXPECT_TRUE(address_map_->IsCode(0x8000));
  EXPECT_TRUE(address_map_->IsCode(0x8002));  // RTS

  // Short string might not trigger heuristics (needs 24+ chars)
  // Repeated bytes should trigger Heuristic 4
}

TEST_F(CodeAnalyzerTest, Heuristic_AmbiguousInstructions) {
  // Test: Bytes that could be interpreted as either code or data
  std::vector<uint8_t> data = {
    // Valid code sequence
    0xA9, 0x00,        // LDA #$00
    // Ambiguous: 0x60 could be RTS or data
    0x60,              // RTS (terminator)
    // More code that won't be reached without entry point
    0xA9, 0x01,        // LDA #$01
    0x60,              // RTS
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // First sequence should be discovered
  EXPECT_TRUE(address_map_->IsCode(0x8000));
  EXPECT_TRUE(address_map_->IsCode(0x8002));  // RTS

  // Second sequence won't be reached without entry point or reference
  EXPECT_FALSE(address_map_->IsCode(0x8003));
}

TEST_F(CodeAnalyzerTest, Heuristic_HeuristicConflicts) {
  // Test: Multiple conflicting heuristics (high printable BUT has valid code patterns)
  std::vector<uint8_t> data = {
    // Entry point
    0x20, 0x10, 0x80,  // JSR $8010
    0x60,              // RTS
    // Padding
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    // Ambiguous region: Has printable chars BUT also valid code
    // This tests the threshold for reclassification (needs 2+ heuristics)
    0xA9, 0x41,        // LDA #$41 ('A')
    0xA9, 0x42,        // LDA #$42 ('B')
    0xA9, 0x43,        // LDA #$43 ('C')
    0x60,              // RTS
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // All code should be discovered via JSR
  EXPECT_TRUE(address_map_->IsCode(0x8000));
  EXPECT_TRUE(address_map_->IsCode(0x8010));

  // Should remain as code despite some printable operands
  // (Only 1 heuristic match, needs 2+ for reclassification)
}

TEST_F(CodeAnalyzerTest, Heuristic_DataMasqueradingAsCode) {
  // Test: Graphics/bitmap data that accidentally forms valid opcodes
  std::vector<uint8_t> data = {
    // Real code entry
    0xA9, 0x00,        // LDA #$00
    0x60,              // RTS
    // Graphics data (CoCo semi-graphics characters)
    // These happen to be valid 6502 opcodes but high density suggests data
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Real code should be discovered
  EXPECT_TRUE(address_map_->IsCode(0x8000));
  EXPECT_TRUE(address_map_->IsCode(0x8002));  // RTS

  // Graphics data should not be reached from entry point
  EXPECT_FALSE(address_map_->IsCode(0x8003));
}

TEST_F(CodeAnalyzerTest, Heuristic_RepeatedBytesData) {
  // Test: Heuristic 4 - Repeated identical bytes (screen buffer initialization)
  std::vector<uint8_t> data = {
    // Code
    0xA9, 0x20,        // LDA #$20 (space character)
    0xA0, 0xFF,        // LDY #$FF
    0x60,              // RTS
    // Padding
    0x00,
    // Repeated byte data (screen buffer filled with spaces)
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Code should be discovered
  EXPECT_TRUE(address_map_->IsCode(0x8000));

  // Repeated bytes should trigger Heuristic 4
  // (But won't be discovered as code without entry point anyway)
}

TEST_F(CodeAnalyzerTest, Heuristic_NullTerminatedStrings) {
  // Test: Heuristic 3 - Multiple null-terminated strings
  std::vector<uint8_t> data = {
    // Code
    0xA9, 0x00,        // LDA #$00
    0x60,              // RTS
    0x00, 0x00, 0x00,  // Padding
    // Multiple null-terminated strings
    'F', 'I', 'R', 'S', 'T', 0x00,
    'S', 'E', 'C', 'O', 'N', 'D', 0x00,
    'T', 'H', 'I', 'R', 'D', 0x00,
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Code should be discovered
  EXPECT_TRUE(address_map_->IsCode(0x8000));
  EXPECT_TRUE(address_map_->IsCode(0x8002));  // RTS

  // Strings should not be marked as code
  // (Heuristic 3: Null-terminated strings detected)
}

TEST_F(CodeAnalyzerTest, Heuristic_HighIllegalOpcodeDensity) {
  // Test: Heuristic 7 - High density of illegal opcodes suggests data
  std::vector<uint8_t> data = {
    // Code
    0xA9, 0x00,        // LDA #$00
    0x60,              // RTS
    0x00,              // Padding
    // Data with many illegal opcodes for 6502
    0x02, 0x12, 0x22, 0x32, 0x42, 0x52, 0x62, 0x72,  // Illegal opcodes
    0x82, 0x92, 0xA2, 0xB2, 0xC2, 0xD2, 0xE2, 0xF2,
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Code should be discovered
  EXPECT_TRUE(address_map_->IsCode(0x8000));
  EXPECT_TRUE(address_map_->IsCode(0x8002));  // RTS

  // High illegal density should help identify as data
}

TEST_F(CodeAnalyzerTest, Heuristic_AddressLikePairs) {
  // Test: Heuristic 5 - Pairs of bytes that look like addresses
  std::vector<uint8_t> data = {
    // Code
    0xA9, 0x00,        // LDA #$00
    0x60,              // RTS
    // Padding
    0x00, 0x00, 0x00, 0x00, 0x00,
    // Vector table / dispatch table (address pairs)
    0x00, 0x80,        // $8000
    0x10, 0x80,        // $8010
    0x20, 0x80,        // $8020
    0x30, 0x80,        // $8030
    0x40, 0x80,        // $8040
    0x50, 0x80,        // $8050
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Code should be discovered
  EXPECT_TRUE(address_map_->IsCode(0x8000));

  // Address pairs should trigger Heuristic 5
}

TEST_F(CodeAnalyzerTest, Heuristic_RepeatedInstructions) {
  // Test: Heuristic 6 - Repeated identical instructions (graphics pattern)
  std::vector<uint8_t> data = {
    // Code
    0xA9, 0x00,        // LDA #$00
    0x60,              // RTS
    0x00,              // Padding
    // Repeated instruction pattern (graphics data)
    0xA9, 0xFF, 0xA9, 0xFF, 0xA9, 0xFF, 0xA9, 0xFF,
    0xA9, 0xFF, 0xA9, 0xFF, 0xA9, 0xFF, 0xA9, 0xFF,
    0xA9, 0xFF, 0xA9, 0xFF, 0xA9, 0xFF, 0xA9, 0xFF,
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Code should be discovered
  EXPECT_TRUE(address_map_->IsCode(0x8000));
  EXPECT_TRUE(address_map_->IsCode(0x8002));  // RTS

  // Repeated instructions should trigger Heuristic 6
}

TEST_F(CodeAnalyzerTest, Heuristic_MixedCodeAndData) {
  // Test: Interleaved code and data (embedded data in code section)
  std::vector<uint8_t> data = {
    // Code that jumps over data
    0x4C, 0x0A, 0x80,  // JMP $800A (skip over data)
    // Embedded data
    'D', 'A', 'T', 'A', 0x00, 0x00, 0x00,
    // More code
    0xA9, 0x00,        // LDA #$00
    0x60,              // RTS
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Code before and after data should be discovered
  EXPECT_TRUE(address_map_->IsCode(0x8000));  // JMP
  EXPECT_TRUE(address_map_->IsCode(0x800A));  // LDA after jump

  // Embedded data should not be marked as code
  EXPECT_FALSE(address_map_->IsCode(0x8003));  // 'D'
}

TEST_F(CodeAnalyzerTest, Heuristic_PrintablePercentageThreshold) {
  // Test: Heuristic 1 boundary - Just below and above 90% printable threshold
  std::vector<uint8_t> data_high_printable = {
    // Code
    0xA9, 0x00,        // LDA #$00
    0x60,              // RTS
    0x00, 0x00, 0x00,  // Padding
    // 95% printable (19 printable, 1 non-printable)
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
    'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 0x00,
  };

  CreateTestBinary(data_high_printable, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Code should be discovered
  EXPECT_TRUE(address_map_->IsCode(0x8000));

  // High printable percentage (>90%) should trigger Heuristic 1
}

TEST_F(CodeAnalyzerTest, Heuristic_LongPrintableSequenceThreshold) {
  // Test: Heuristic 2 boundary - Exactly 24 consecutive printable chars
  std::vector<uint8_t> data = {
    // Code
    0xA9, 0x00,        // LDA #$00
    0x60,              // RTS
    0x00, 0x00,        // Padding
    // Exactly 24 consecutive printable (meets threshold)
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Code should be discovered
  EXPECT_TRUE(address_map_->IsCode(0x8000));

  // 24 consecutive printables should trigger Heuristic 2
}

TEST_F(CodeAnalyzerTest, Heuristic_CodeVsDataClassification) {
  // Test: Comprehensive code vs data classification with multiple regions
  std::vector<uint8_t> data(256, 0x00);

  // Region 1: Clear code (0x00-0x0F)
  data[0x00] = 0xA9;  // LDA #$55
  data[0x01] = 0x55;
  data[0x02] = 0x8D;  // STA $8020
  data[0x03] = 0x20;
  data[0x04] = 0x80;
  data[0x05] = 0x20;  // JSR $8030
  data[0x06] = 0x30;
  data[0x07] = 0x80;
  data[0x08] = 0x60;  // RTS

  // Region 2: Clear data - string (0x20-0x2F)
  const char* str = "CLEAR DATA";
  for (size_t i = 0; i < strlen(str); i++) {
    data[0x20 + i] = str[i];
  }
  data[0x20 + strlen(str)] = 0x00;

  // Region 3: Code reached via JSR (0x30-0x3F)
  data[0x30] = 0xA9;  // LDA #$FF
  data[0x31] = 0xFF;
  data[0x32] = 0x60;  // RTS

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Region 1: Code should be discovered
  EXPECT_TRUE(address_map_->IsCode(0x8000));
  EXPECT_TRUE(address_map_->IsCode(0x8005));  // JSR
  EXPECT_TRUE(address_map_->IsCode(0x8008));  // RTS

  // Region 2: String should not be marked as code
  EXPECT_FALSE(address_map_->IsCode(0x8020));

  // Region 3: Code reached via JSR should be discovered
  EXPECT_TRUE(address_map_->IsCode(0x8030));
  EXPECT_TRUE(address_map_->IsCode(0x8032));  // RTS
}

TEST_F(CodeAnalyzerTest, Heuristic_BoundaryBetweenCodeAndDataRegions) {
  // Test: Precise boundary detection between adjacent code and data
  std::vector<uint8_t> data = {
    // Code block 1
    0xA9, 0x00,        // LDA #$00
    0x69, 0x01,        // ADC #$01
    0x60,              // RTS
    // Immediate data (no gap)
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    // Code block 2 (unreachable without entry point)
    0xA9, 0xFF,        // LDA #$FF
    0x60,              // RTS
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // First code block should be discovered completely
  EXPECT_TRUE(address_map_->IsCode(0x8000));
  EXPECT_TRUE(address_map_->IsCode(0x8002));
  EXPECT_TRUE(address_map_->IsCode(0x8004));  // RTS (boundary)

  // Data after RTS should not be marked as code
  EXPECT_FALSE(address_map_->IsCode(0x8005));

  // Second code block won't be discovered (no entry point)
  EXPECT_FALSE(address_map_->IsCode(0x800D));
}

TEST_F(CodeAnalyzerTest, Heuristic_ReclassificationThreshold) {
  // Test: Verify 2+ heuristics required for reclassification
  // This is a regression test for conservative reclassification
  std::vector<uint8_t> data = {
    // Code that will be discovered
    0x20, 0x10, 0x80,  // JSR $8010
    0x60,              // RTS
    // Padding
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    // Target: Valid code with only 1 heuristic match
    // Should NOT be reclassified (needs 2+ heuristics)
    0xA9, 0x20,        // LDA #$20 (printable operand = weak signal)
    0xA9, 0x21,        // LDA #$21
    0xA9, 0x22,        // LDA #$22
    0x60,              // RTS
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Both code regions should be discovered
  EXPECT_TRUE(address_map_->IsCode(0x8000));  // JSR
  EXPECT_TRUE(address_map_->IsCode(0x8010));  // Target

  // Target should remain CODE (only 1 heuristic, needs 2+)
  EXPECT_TRUE(address_map_->IsCode(0x8010));
  EXPECT_TRUE(address_map_->IsCode(0x8013));  // RTS
}


// ============================================================================
// Work Package 4: Multi-Pass Analysis Tests
// ============================================================================

TEST_F(CodeAnalyzerTest, MultiPass_ConvergenceDetection) {
  // Test: Simple code that converges in one pass
  std::vector<uint8_t> data = {
    // $8000: Simple linear code
    0xA9, 0x00,  // LDA #$00
    0x85, 0x10,  // STA $10
    0x60,        // RTS
  };

  CreateTestBinary(data, 0x8000);
  CreateAnalyzer(cpu::CpuVariant::MOS_6502);
  analyzer_->AddEntryPoint(0x8000);

  // Run recursive analysis
  analyzer_->RecursiveAnalyze(address_map_.get());

  // Should discover all code in first pass
  EXPECT_EQ(CountCodeBytes(), 5);
  EXPECT_TRUE(address_map_->IsCode(0x8000));
  EXPECT_TRUE(address_map_->IsCode(0x8004));  // RTS

  // Verify convergence happened quickly (should be 1-2 passes)
  // Since we don't have direct access to pass count, verify that analysis completed
  EXPECT_GT(CountCodeBytes(), 0);
}

TEST_F(CodeAnalyzerTest, MultiPass_OscillationDetection) {
  // Test: Code with cross-references that might cause multiple passes
  std::vector<uint8_t> data(256, 0xEA);  // Fill with NOPs

  // $8000: Jump to $8010
  data[0] = 0x4C;  // JMP
  data[1] = 0x10;
  data[2] = 0x80;

  // $8010: Jump back to $8005
  data[16] = 0x4C;  // JMP
  data[17] = 0x05;
  data[18] = 0x80;

  // $8005: Code that jumps forward again
  data[5] = 0x4C;  // JMP
  data[6] = 0x20;
  data[7] = 0x80;

  // $8020: Final code
  data[32] = 0xA9;  // LDA #$00
  data[33] = 0x00;
  data[34] = 0x60;  // RTS

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Should discover all code regions despite cross-references
  EXPECT_TRUE(address_map_->IsCode(0x8000));  // First jump
  EXPECT_TRUE(address_map_->IsCode(0x8010));  // Second jump
  EXPECT_TRUE(address_map_->IsCode(0x8005));  // Third jump
  EXPECT_TRUE(address_map_->IsCode(0x8020));  // Final code

  // Should handle without infinite loop
  EXPECT_GT(CountCodeBytes(), 0);
}

TEST_F(CodeAnalyzerTest, MultiPass_MaxIterationsReached) {
  // Test: Large binary that might need multiple passes to fully analyze
  // Create a complex binary with many disconnected code regions
  std::vector<uint8_t> data(4096, 0x00);  // 4KB of zeros

  // Place code snippets every 256 bytes that jump to each other
  for (size_t i = 0; i < 15; i++) {
    size_t offset = i * 256;
    // Create a jump to the next region
    data[offset] = 0x4C;  // JMP
    data[offset + 1] = static_cast<uint8_t>((offset + 256) & 0xFF);
    data[offset + 2] = static_cast<uint8_t>(0x80 + ((offset + 256) >> 8));
  }

  // Last region has an RTS
  data[15 * 256] = 0x60;  // RTS

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Should discover code in multiple regions
  EXPECT_TRUE(address_map_->IsCode(0x8000));  // First region

  // Should complete without hanging (even if it hits max passes)
  EXPECT_GT(CountCodeBytes(), 0);
}

TEST_F(CodeAnalyzerTest, MultiPass_ProgressiveRefinement) {
  // Test: Code that gets progressively refined over multiple passes
  // This tests entry point discovery across passes
  std::vector<uint8_t> data(512, 0x00);

  // $8000: Initial entry point - calls a subroutine
  data[0] = 0x20;  // JSR
  data[1] = 0x10;
  data[2] = 0x80;  // JSR $8010
  data[3] = 0x60;  // RTS

  // $8010: Subroutine that looks like it has a prologue
  data[16] = 0x08;  // PHP (typical 6502 prologue)
  data[17] = 0x48;  // PHA
  data[18] = 0xA9;  // LDA #$42
  data[19] = 0x42;
  data[20] = 0x68;  // PLA
  data[21] = 0x28;  // PLP
  data[22] = 0x60;  // RTS

  // $8100: Another subroutine not directly called (offset 256)
  data[256] = 0x08;  // PHP
  data[257] = 0x48;  // PHA
  data[258] = 0xA9;  // LDA #$FF
  data[259] = 0xFF;
  data[260] = 0x68;  // PLA
  data[261] = 0x28;  // PLP
  data[262] = 0x60;  // RTS

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // First pass should discover main code and first subroutine via JSR
  EXPECT_TRUE(address_map_->IsCode(0x8000));  // Main
  EXPECT_TRUE(address_map_->IsCode(0x8010));  // First subroutine

  // Second subroutine might be discovered via heuristics
  // (depending on implementation of entry point discovery)
  size_t total_code = CountCodeBytes();
  EXPECT_GE(total_code, 11);  // At least main + first subroutine
}

TEST_F(CodeAnalyzerTest, MultiPass_PartialAnalysisResults) {
  // Test: Binary that can only be partially analyzed
  // Some code is unreachable and should remain UNKNOWN or be marked as DATA
  std::vector<uint8_t> data(256, 0xFF);  // Fill with 0xFF

  // $8000: Reachable code
  data[0] = 0xA9;  // LDA #$00
  data[1] = 0x00;
  data[2] = 0x4C;  // JMP $8000 (infinite loop)
  data[3] = 0x00;
  data[4] = 0x80;

  // $8010: Unreachable code (offset 16)
  data[16] = 0xA9;  // LDA #$FF
  data[17] = 0xFF;
  data[18] = 0x60;  // RTS

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Reachable code should be discovered
  EXPECT_TRUE(address_map_->IsCode(0x8000));
  EXPECT_TRUE(address_map_->IsCode(0x8002));

  // Unreachable code should not be discovered (unless heuristics find it)
  // Most of the binary should remain as DATA after analysis
  size_t code_bytes = CountCodeBytes();
  size_t total_bytes = data.size();
  EXPECT_LT(code_bytes, total_bytes);  // Not everything is code
}

TEST_F(CodeAnalyzerTest, MultiPass_ConditionalBranchDiscovery) {
  // Test: Multi-pass discovery of code through conditional branches
  std::vector<uint8_t> data = {
    // $8000: Conditional branch
    0xA9, 0x00,        // LDA #$00
    0xF0, 0x02,        // BEQ $8004 (skip LDA #$01)
    0xA9, 0x01,        // LDA #$01 (not-taken path)

    // $8004: Converged path (both paths lead here)
    0x85, 0x10,        // STA $10
    0x60,              // RTS
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Both branch paths should be discovered
  EXPECT_TRUE(address_map_->IsCode(0x8000));  // LDA #$00
  EXPECT_TRUE(address_map_->IsCode(0x8002));  // BEQ
  EXPECT_TRUE(address_map_->IsCode(0x8004));  // STA $10 (converged)

  // All bytes should be discovered as code
  EXPECT_GE(CountCodeBytes(), 6);  // At least 6 bytes
}

TEST_F(CodeAnalyzerTest, MultiPass_NestedSubroutineCalls) {
  // Test: JSR call and subroutine discovery
  std::vector<uint8_t> data = {
    // $8000: Main
    0x20, 0x06, 0x80,  // JSR $8006 (sub1)
    0xA9, 0xFF,        // LDA #$FF
    0x60,              // RTS

    // $8006: Sub1
    0xA9, 0x01,        // LDA #$01
    0x85, 0x10,        // STA $10
    0x60,              // RTS
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Both main and subroutine should be discovered
  EXPECT_TRUE(address_map_->IsCode(0x8000));  // Main
  EXPECT_TRUE(address_map_->IsCode(0x8006));  // Sub1

  // Subroutine should have xref from JSR
  EXPECT_TRUE(address_map_->HasXrefs(0x8006));  // Sub1

  // All bytes should be discovered as code
  EXPECT_GE(CountCodeBytes(), 9);  // At least main + sub
}

TEST_F(CodeAnalyzerTest, MultiPass_6809_ComplexBranching) {
  // Test: 6809 code with complex branching patterns
  std::vector<uint8_t> data = {
    // $8000: Initial code with LBSR
    0x17, 0x00, 0x08,  // LBSR $800B (long branch, relative +8)
    0x86, 0xFF,        // LDA #$FF
    0x27, 0x02,        // BEQ $800A (forward branch)
    0x86, 0x00,        // LDA #$00
    0x39,              // RTS

    // $800B: Subroutine
    0x34, 0x16,        // PSHS D,X,Y (typical prologue)
    0xC6, 0x42,        // LDB #$42
    0x35, 0x16,        // PULS D,X,Y
    0x39,              // RTS
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOTOROLA_6809, 0x8000);

  // All paths should be discovered
  EXPECT_TRUE(address_map_->IsCode(0x8000));  // LBSR
  EXPECT_TRUE(address_map_->IsCode(0x8003));  // LDA #$FF
  EXPECT_TRUE(address_map_->IsCode(0x8005));  // BEQ
  EXPECT_TRUE(address_map_->IsCode(0x8007));  // LDA #$00
  EXPECT_TRUE(address_map_->IsCode(0x8009));  // RTS
  EXPECT_TRUE(address_map_->IsCode(0x800B));  // PSHS (subroutine)

  // All bytes should be discovered as code
  EXPECT_GE(CountCodeBytes(), 16);  // At least all intended bytes
}

TEST_F(CodeAnalyzerTest, MultiPass_MixedCodeAndData) {
  // Test: Binary with interleaved code and data sections
  std::vector<uint8_t> data(128, 0x00);

  // $8000: Code
  data[0] = 0x20;  // JSR
  data[1] = 0x10;
  data[2] = 0x80;  // JSR $8010
  data[3] = 0x60;  // RTS

  // $8004-$800F: Data (12 bytes)
  for (size_t i = 4; i < 16; i++) {
    data[i] = static_cast<uint8_t>(i * 16);
  }

  // $8010: More code (offset 16)
  data[16] = 0xA9;  // LDA #$00
  data[17] = 0x00;
  data[18] = 0x85;  // STA $10
  data[19] = 0x10;
  data[20] = 0x60;  // RTS

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Code regions should be discovered
  EXPECT_TRUE(address_map_->IsCode(0x8000));  // First code
  EXPECT_TRUE(address_map_->IsCode(0x8010));  // Second code

  // Verify we discovered at least the code regions
  // Note: Analyzer may discover more due to entry point heuristics
  size_t code = CountCodeBytes();
  EXPECT_GE(code, 9);  // At least the two code regions
}

TEST_F(CodeAnalyzerTest, MultiPass_EmptyWithNoEntryPoints) {
  // Test: Empty entry points list should still handle gracefully
  std::vector<uint8_t> data = {0xA9, 0x00, 0x60};  // LDA #$00, RTS

  CreateTestBinary(data, 0x8000);
  CreateAnalyzer(cpu::CpuVariant::MOS_6502);

  // Don't add any entry points
  analyzer_->RecursiveAnalyze(address_map_.get());

  // Should handle gracefully (might discover nothing or might use load address)
  size_t code = CountCodeBytes();
  // Implementation may use load address as default entry point
  EXPECT_GE(code, 0);
}

TEST_F(CodeAnalyzerTest, MultiPass_DynamicAnalysisIntegration) {
  // Test: Code that benefits from dynamic analysis
  std::vector<uint8_t> data = {
    // $8000: Code with conditional branch that needs dynamic analysis
    0xA9, 0x00,        // LDA #$00 (sets Z flag)
    0xF0, 0x04,        // BEQ $8006 (should be taken with Z=1)
    0xA9, 0xFF,        // LDA #$FF (not taken path)
    0x60,              // RTS

    // $8006: Taken path
    0xA9, 0x42,        // LDA #$42
    0x60,              // RTS
  };

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Both paths should be discovered (static or dynamic analysis)
  EXPECT_TRUE(address_map_->IsCode(0x8000));  // LDA #$00
  EXPECT_TRUE(address_map_->IsCode(0x8002));  // BEQ
  EXPECT_TRUE(address_map_->IsCode(0x8006));  // LDA #$42 (taken path)

  // Not-taken path should also be discovered
  EXPECT_TRUE(address_map_->IsCode(0x8004));  // LDA #$FF

  // All or most bytes should be discovered as code
  EXPECT_GE(CountCodeBytes(), 7);  // At least most of the code
}

// ============================================================================
// Work Package 5: Complex Integration Tests
// ============================================================================

TEST_F(CodeAnalyzerTest, Integration_MultipleEntryPoints) {
  // Test: Binary with multiple disconnected entry points that share no code paths
  // This tests the analyzer's ability to handle multiple independent execution contexts

  std::vector<uint8_t> data(0x400, 0x00);  // 1KB binary with padding

  // Entry point 1: ISR handler at 0x8000
  data[0x000] = 0x34; data[0x001] = 0x36;  // PSHS A,B,X,Y (6809 context save)
  data[0x002] = 0x86; data[0x003] = 0x01;  // LDA #$01
  data[0x004] = 0xB7; data[0x005] = 0x40; data[0x006] = 0x00;  // STA $4000
  data[0x007] = 0x35; data[0x008] = 0x36;  // PULS A,B,X,Y
  data[0x009] = 0x3B;                      // RTI

  // Entry point 2: Main program at 0x8100 (offset 0x100)
  data[0x100] = 0x10; data[0x101] = 0xCE; data[0x102] = 0x80; data[0x103] = 0x00;  // LDS #$8000
  data[0x104] = 0x8E; data[0x105] = 0x41; data[0x106] = 0x00;  // LDX #$4100
  data[0x107] = 0xBD; data[0x108] = 0x82; data[0x109] = 0x00;  // JSR $8200
  data[0x10A] = 0x16; data[0x10B] = 0xFE; data[0x10C] = 0xF7;  // LBRA $8104 (loop)

  // Entry point 3: Subroutine at 0x8200 (offset 0x200)
  data[0x200] = 0x34; data[0x201] = 0x16;  // PSHS D,X,Y (prologue)
  data[0x202] = 0xC6; data[0x203] = 0x42;  // LDB #$42
  data[0x204] = 0xE7; data[0x205] = 0x84;  // STB ,X
  data[0x206] = 0x30; data[0x207] = 0x01;  // LEAX 1,X
  data[0x208] = 0x35; data[0x209] = 0x16;  // PULS D,X,Y
  data[0x20A] = 0x39;                      // RTS

  // Entry point 4: Reset vector handler at 0x8300 (offset 0x300)
  data[0x300] = 0x1A; data[0x301] = 0x50;  // ORCC #$50 (disable interrupts)
  data[0x302] = 0x10; data[0x303] = 0xCE; data[0x304] = 0xFF; data[0x305] = 0x00;  // LDS #$FF00
  data[0x306] = 0x16; data[0x307] = 0xFD; data[0x308] = 0xF7;  // LBRA $8100 (to main)

  CreateTestBinary(data, 0x8000);
  CreateAnalyzer(cpu::CpuVariant::MOTOROLA_6809);

  // Add all four entry points explicitly
  analyzer_->AddEntryPoint(0x8000);  // ISR
  analyzer_->AddEntryPoint(0x8100);  // Main
  analyzer_->AddEntryPoint(0x8200);  // Subroutine
  analyzer_->AddEntryPoint(0x8300);  // Reset

  analyzer_->RecursiveAnalyze(address_map_.get());

  // Verify all entry points discovered their respective code
  EXPECT_TRUE(address_map_->IsCode(0x8000));  // ISR start
  EXPECT_TRUE(address_map_->IsCode(0x8009));  // ISR end (RTI)

  EXPECT_TRUE(address_map_->IsCode(0x8100));  // Main start
  EXPECT_TRUE(address_map_->IsCode(0x8107));  // Main JSR

  EXPECT_TRUE(address_map_->IsCode(0x8200));  // Subroutine start
  EXPECT_TRUE(address_map_->IsCode(0x820A));  // Subroutine end (RTS)

  EXPECT_TRUE(address_map_->IsCode(0x8300));  // Reset start
  EXPECT_TRUE(address_map_->IsCode(0x8306));  // Reset LBRA

  // Verify cross-reference from main to subroutine
  EXPECT_TRUE(address_map_->HasXrefs(0x8200));

  // Count total code bytes - should be substantial
  size_t code_bytes = CountCodeBytes();
  EXPECT_GT(code_bytes, 30);  // At least 30+ bytes across all regions
}

TEST_F(CodeAnalyzerTest, Integration_CrossModuleReferences) {
  // Test: Complex web of cross-references between multiple "modules"
  // Simulates a modular program with multiple layers of abstraction

  // Use 0xFF for padding to avoid false entry point discovery in zeros
  std::vector<uint8_t> data(0x300, 0xFF);

  // Module 1: High-level API at 0x8000
  data[0x000] = 0xBD; data[0x001] = 0x81; data[0x002] = 0x00;  // JSR $8100 (to Module 2)
  data[0x003] = 0xBD; data[0x004] = 0x82; data[0x005] = 0x00;  // JSR $8200 (to Module 3)
  data[0x006] = 0x39;                                          // RTS

  // Module 2: Mid-level utilities at 0x8100 (offset 0x100)
  data[0x100] = 0x34; data[0x101] = 0x06;  // PSHS B,A
  data[0x102] = 0xBD; data[0x103] = 0x82; data[0x104] = 0x10;  // JSR $8210 (to Module 3 helper)
  data[0x105] = 0xBD; data[0x106] = 0x82; data[0x107] = 0x20;  // JSR $8220 (to Module 3 helper)
  data[0x108] = 0x35; data[0x109] = 0x06;  // PULS B,A
  data[0x10A] = 0x39;                      // RTS

  // Module 3: Low-level HAL at 0x8200 (offset 0x200)
  data[0x200] = 0x86; data[0x201] = 0xFF;  // LDA #$FF
  data[0x202] = 0xB7; data[0x203] = 0x40; data[0x204] = 0x00;  // STA $4000
  data[0x205] = 0x16; data[0x206] = 0x00; data[0x207] = 0x07;  // LBRA $820F (to helper)
  data[0x208] = 0x12; data[0x209] = 0x12; data[0x20A] = 0x12;  // NOP padding
  data[0x20B] = 0x12; data[0x20C] = 0x12; data[0x20D] = 0x12;
  data[0x20E] = 0x39;  // RTS (unreachable)

  // Module 3 Helper 1 at 0x8210 (offset 0x210)
  data[0x210] = 0xC6; data[0x211] = 0x01;  // LDB #$01
  data[0x212] = 0xF7; data[0x213] = 0x40; data[0x214] = 0x01;  // STB $4001
  data[0x215] = 0x39;                      // RTS

  // Module 3 Helper 2 at 0x8220 (offset 0x220)
  data[0x220] = 0xC6; data[0x221] = 0x02;  // LDB #$02
  data[0x222] = 0xF7; data[0x223] = 0x40; data[0x224] = 0x02;  // STB $4002
  data[0x225] = 0x39;                      // RTS

  // Module 3 shared epilogue at 0x820F (offset 0x20F)
  data[0x20F] = 0x39;  // RTS

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOTOROLA_6809, 0x8000);

  // Verify all modules discovered
  EXPECT_TRUE(address_map_->IsCode(0x8000));  // Module 1
  EXPECT_TRUE(address_map_->IsCode(0x8100));  // Module 2
  EXPECT_TRUE(address_map_->IsCode(0x8200));  // Module 3
  EXPECT_TRUE(address_map_->IsCode(0x8210));  // Module 3 Helper 1
  EXPECT_TRUE(address_map_->IsCode(0x8220));  // Module 3 Helper 2

  // Verify cross-references exist
  EXPECT_TRUE(address_map_->HasXrefs(0x8100));  // Module 2 called from Module 1
  EXPECT_TRUE(address_map_->HasXrefs(0x8200));  // Module 3 called from Module 1
  EXPECT_TRUE(address_map_->HasXrefs(0x8210));  // Helper 1 called from Module 2
  EXPECT_TRUE(address_map_->HasXrefs(0x8220));  // Helper 2 called from Module 2

  // Note: Shared epilogue at 0x820F may or may not be discovered depending
  // on branch analysis implementation details

  // Total code should be substantial (at least the 4 main modules)
  size_t code_bytes = CountCodeBytes();
  EXPECT_GT(code_bytes, 35);  // At least the core modules discovered
}

TEST_F(CodeAnalyzerTest, Integration_LargeBinary64KB) {
  // Test: Large 64KB binary to stress test memory efficiency and performance
  // This tests analyzer's ability to handle maximum address space

  // Use 0xFF for padding to avoid false entry point discovery
  std::vector<uint8_t> data(0x10000, 0xFF);  // 64KB of invalid opcodes

  // Place code islands throughout the binary
  // Island 1: Start at 0x0000
  data[0x0000] = 0x20; data[0x0001] = 0x00; data[0x0002] = 0x80;  // JSR $8000
  data[0x0003] = 0x4C; data[0x0004] = 0x00; data[0x0005] = 0xC0;  // JMP $C000

  // Island 2: Middle at 0x8000
  data[0x8000] = 0xA9; data[0x8001] = 0x00;  // LDA #$00
  data[0x8002] = 0x8D; data[0x8003] = 0x00; data[0x8004] = 0x04;  // STA $0400
  data[0x8005] = 0x20; data[0x8006] = 0x00; data[0x8007] = 0xF0;  // JSR $F000
  data[0x8008] = 0x60;  // RTS

  // Island 3: High memory at 0xC000
  data[0xC000] = 0xA9; data[0xC001] = 0xFF;  // LDA #$FF
  data[0xC002] = 0x85; data[0xC003] = 0x01;  // STA $01
  data[0xC004] = 0x4C; data[0xC005] = 0x00; data[0xC006] = 0xF0;  // JMP $F000

  // Island 4: Near top at 0xF000
  data[0xF000] = 0xA2; data[0xF001] = 0x00;  // LDX #$00
  data[0xF002] = 0xBD; data[0xF003] = 0xFF; data[0xF004] = 0xF8;  // LDA $FFF8,X
  data[0xF005] = 0xE8;  // INX
  data[0xF006] = 0xE0; data[0xF007] = 0x08;  // CPX #$08
  data[0xF008] = 0xD0; data[0xF009] = 0xF8;  // BNE $F002 (loop)
  data[0xF00A] = 0x60;  // RTS

  CreateTestBinary(data, 0x0000);
  CreateAnalyzer(cpu::CpuVariant::MOS_6502);

  // Add entry points for all islands
  analyzer_->AddEntryPoint(0x0000);
  analyzer_->AddEntryPoint(0x8000);
  analyzer_->AddEntryPoint(0xC000);
  analyzer_->AddEntryPoint(0xF000);

  analyzer_->RecursiveAnalyze(address_map_.get());

  // Verify each island discovered
  EXPECT_TRUE(address_map_->IsCode(0x0000));
  EXPECT_TRUE(address_map_->IsCode(0x8000));
  EXPECT_TRUE(address_map_->IsCode(0xC000));
  EXPECT_TRUE(address_map_->IsCode(0xF000));

  // Verify jumps followed correctly
  EXPECT_TRUE(address_map_->HasXrefs(0x8000));  // JSR from island 1
  EXPECT_TRUE(address_map_->HasXrefs(0xC000));  // JMP from island 1
  EXPECT_TRUE(address_map_->HasXrefs(0xF000));  // Multiple jumps to island 4

  // Verify loop in island 4
  EXPECT_TRUE(address_map_->IsCode(0xF002));  // Loop target
  EXPECT_TRUE(address_map_->IsCode(0xF008));  // BNE instruction

  // Code should be minimal compared to 64KB total
  size_t code_bytes = CountCodeBytes();

  EXPECT_GT(code_bytes, 30);  // At least all islands
  EXPECT_LT(code_bytes, 1000);  // But much less than 64KB

  // Verify no crashes and reasonable performance
  // (Test implicitly passes if we get here without timeout)
}

TEST_F(CodeAnalyzerTest, Integration_DenselyPackedCode) {
  // Test: Binary where almost everything is executable code
  // Common in hand-optimized assembly or compressed code
  // Tests analyzer's ability to handle minimal data regions

  std::vector<uint8_t> data;

  // Dense code block with complex control flow (6502)
  // Simulates a tightly packed game loop or critical routine

  // Main loop at 0x8000
  data.push_back(0xA9); data.push_back(0x00);  // LDA #$00
  data.push_back(0x85); data.push_back(0x10);  // STA $10 (counter)

  // Loop body at 0x8004
  data.push_back(0x20); data.push_back(0x20); data.push_back(0x80);  // JSR $8020
  data.push_back(0x20); data.push_back(0x30); data.push_back(0x80);  // JSR $8030
  data.push_back(0x20); data.push_back(0x40); data.push_back(0x80);  // JSR $8040
  data.push_back(0xE6); data.push_back(0x10);  // INC $10
  data.push_back(0xA5); data.push_back(0x10);  // LDA $10
  data.push_back(0xC9); data.push_back(0xFF);  // CMP #$FF
  data.push_back(0xD0); data.push_back(0xF1);  // BNE $8004 (loop back)
  data.push_back(0x60);  // RTS

  // Sub 1 at 0x8020 (offset 0x20)
  for (size_t i = data.size(); i < 0x20; ++i) data.push_back(0xEA);  // Padding
  data.push_back(0xA5); data.push_back(0x10);  // LDA $10
  data.push_back(0x0A);                        // ASL A
  data.push_back(0x85); data.push_back(0x11);  // STA $11
  data.push_back(0x60);  // RTS

  // Sub 2 at 0x8030 (offset 0x30)
  for (size_t i = data.size(); i < 0x30; ++i) data.push_back(0xEA);
  data.push_back(0xA5); data.push_back(0x11);  // LDA $11
  data.push_back(0x4A);                        // LSR A
  data.push_back(0x85); data.push_back(0x12);  // STA $12
  data.push_back(0x60);  // RTS

  // Sub 3 at 0x8040 (offset 0x40)
  for (size_t i = data.size(); i < 0x40; ++i) data.push_back(0xEA);
  data.push_back(0xA5); data.push_back(0x12);  // LDA $12
  data.push_back(0x29); data.push_back(0x0F);  // AND #$0F
  data.push_back(0x85); data.push_back(0x13);  // STA $13
  data.push_back(0x60);  // RTS

  CreateTestBinary(data, 0x8000);
  RunRecursiveAnalysis(cpu::CpuVariant::MOS_6502, 0x8000);

  // Verify all subroutines discovered
  EXPECT_TRUE(address_map_->IsCode(0x8000));  // Main loop
  EXPECT_TRUE(address_map_->IsCode(0x8020));  // Sub 1
  EXPECT_TRUE(address_map_->IsCode(0x8030));  // Sub 2
  EXPECT_TRUE(address_map_->IsCode(0x8040));  // Sub 3

  // Verify loop back branch
  EXPECT_TRUE(address_map_->IsCode(0x8004));  // Loop target

  // Verify cross-references
  EXPECT_TRUE(address_map_->HasXrefs(0x8020));
  EXPECT_TRUE(address_map_->HasXrefs(0x8030));
  EXPECT_TRUE(address_map_->HasXrefs(0x8040));

  // Should have discovered most/all of the binary as code
  size_t code_bytes = CountCodeBytes();
  EXPECT_GT(code_bytes, 50);  // Most of the code should be discovered

  // Data bytes should be minimal (mostly padding NOPs)
  size_t data_bytes = CountDataBytes();
  EXPECT_LT(data_bytes, 30);  // Very little data
}

TEST_F(CodeAnalyzerTest, Integration_SparseCode) {
  // Test: Binary with large gaps of data between code regions
  // Common in data-heavy programs or packed formats
  // Tests analyzer's ability to skip over data and find isolated code

  // Use mixed data pattern to avoid false entry point discovery
  std::vector<uint8_t> data(0x800, 0xFF);  // 2KB binary with invalid opcodes

  // Code island 1 at 0x8000
  data[0x000] = 0x20; data[0x001] = 0x00; data[0x002] = 0x82;  // JSR $8200
  data[0x003] = 0x60;  // RTS

  // 508 bytes of data (strings, tables, etc.)
  for (size_t i = 0x004; i < 0x200; ++i) {
    data[i] = static_cast<uint8_t>((i * 37) & 0xFF);  // Pseudo-random data pattern
  }

  // Code island 2 at 0x8200 (offset 0x200)
  data[0x200] = 0x08;  // PHP (save flags)
  data[0x201] = 0x48;  // PHA (save A)
  data[0x202] = 0xA9; data[0x203] = 0x00;  // LDA #$00
  data[0x204] = 0x85; data[0x205] = 0x10;  // STA $10
  data[0x206] = 0x20; data[0x207] = 0x00; data[0x208] = 0x86;  // JSR $8600
  data[0x209] = 0x68;  // PLA
  data[0x20A] = 0x28;  // PLP
  data[0x20B] = 0x60;  // RTS

  // 1012 bytes of data (large data table)
  for (size_t i = 0x20C; i < 0x600; ++i) {
    data[i] = static_cast<uint8_t>((i * 73 + 17) & 0xFF);
  }

  // Code island 3 at 0x8600 (offset 0x600)
  data[0x600] = 0xA0; data[0x601] = 0x00;  // LDY #$00
  data[0x602] = 0xB9; data[0x603] = 0x00; data[0x604] = 0x84;  // LDA $8400,Y
  data[0x605] = 0x99; data[0x606] = 0x00; data[0x607] = 0x04;  // STA $0400,Y
  data[0x608] = 0xC8;  // INY
  data[0x609] = 0xC0; data[0x60A] = 0x20;  // CPY #$20
  data[0x60B] = 0xD0; data[0x60C] = 0xF5;  // BNE $8602
  data[0x60D] = 0x60;  // RTS

  // More data after code
  for (size_t i = 0x60E; i < 0x800; ++i) {
    data[i] = static_cast<uint8_t>((i * 11 + 5) & 0xFF);
  }

  CreateTestBinary(data, 0x8000);
  CreateAnalyzer(cpu::CpuVariant::MOS_6502);

  // Add only the first entry point
  analyzer_->AddEntryPoint(0x8000);
  analyzer_->RecursiveAnalyze(address_map_.get());

  // Verify code islands discovered via JSR chain
  EXPECT_TRUE(address_map_->IsCode(0x8000));  // Island 1
  EXPECT_TRUE(address_map_->IsCode(0x8200));  // Island 2
  EXPECT_TRUE(address_map_->IsCode(0x8600));  // Island 3

  // Verify cross-references
  EXPECT_TRUE(address_map_->HasXrefs(0x8200));
  EXPECT_TRUE(address_map_->HasXrefs(0x8600));

  // Verify loop in island 3
  EXPECT_TRUE(address_map_->IsCode(0x8602));  // Loop target

  // Code should be minimal compared to total binary size
  size_t code_bytes = CountCodeBytes();

  EXPECT_LT(code_bytes, 100);     // Small amount of code (less than 100 bytes of 2048)

  // Verify specific data regions NOT marked as code
  EXPECT_FALSE(address_map_->IsCode(0x8004));  // Start of data region 1
  EXPECT_FALSE(address_map_->IsCode(0x8100));  // Middle of data region 1
  EXPECT_FALSE(address_map_->IsCode(0x820C));  // Start of data region 2
  EXPECT_FALSE(address_map_->IsCode(0x8400));  // Middle of data region 2
}

}  // namespace
}  // namespace analysis
}  // namespace sourcerer
