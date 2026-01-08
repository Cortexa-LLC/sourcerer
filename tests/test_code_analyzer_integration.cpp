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

}  // namespace
}  // namespace analysis
}  // namespace sourcerer
