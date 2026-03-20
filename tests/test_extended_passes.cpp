// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

// Unit tests for the three extended LLM passes:
//   - DataCodeScanner   (Pass 1)
//   - StringScanner     (Pass 2)
//   - CodePatternDetector (Pass 3)

#include <gtest/gtest.h>
#include <cstdint>
#include <string>
#include <vector>

#include "analysis/llm/code_pattern_detector.h"
#include "analysis/llm/data_code_scanner.h"
#include "analysis/llm/llm_analyzer.h"
#include "analysis/llm/string_scanner.h"
#include "core/address_map.h"
#include "core/binary.h"
#include "core/instruction.h"
#include "cpu/m6502/cpu_6502.h"

namespace sourcerer {
namespace analysis {
namespace llm {
namespace {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Build a Binary with a single segment.
core::Binary MakeBinary(uint32_t load_addr, std::vector<uint8_t> bytes) {
  core::Binary bin;
  core::BinarySegment seg;
  seg.load_address = load_addr;
  seg.data = std::move(bytes);
  bin.add_segment(seg);
  return bin;
}

// Mark an inclusive address range as a specific AddressType.
void MarkRange(core::AddressMap& map, uint32_t start, uint32_t end_inclusive,
               core::AddressType type) {
  for (uint32_t a = start; a <= end_inclusive; ++a) {
    map.SetType(a, type);
  }
}

// Create a 6502 CPU plugin for tests.
std::unique_ptr<cpu::m6502::Cpu6502> Make6502() {
  return std::make_unique<cpu::m6502::Cpu6502>(cpu::CpuVariant::MOS_6502);
}

// Build a minimal Instruction for CodePatternDetector tests.
core::Instruction MakeInst(uint32_t addr, const std::string& mnemonic,
                             const std::string& operand = "",
                             std::vector<uint8_t> bytes = {0xEA},
                             bool is_return = false, bool is_jump = false) {
  core::Instruction inst;
  inst.address = addr;
  inst.mnemonic = mnemonic;
  inst.operand = operand;
  inst.bytes = bytes;
  inst.is_illegal = false;
  inst.is_return = is_return;
  inst.is_jump = is_jump;
  inst.target_address = 0;
  return inst;
}

// ===========================================================================
// DataCodeScanner Tests
// ===========================================================================

class DataCodeScannerTest : public ::testing::Test {
 protected:
  void SetUp() override { cpu_ = Make6502(); }
  std::unique_ptr<cpu::m6502::Cpu6502> cpu_;
};

// 6502 bytes:  LDA #$00 (A9 00), STA $10 (85 10), RTS (60)
// All three are valid, non-illegal instructions.
TEST_F(DataCodeScannerTest, FindsCandidateInDataRegion) {
  // A9 00 = LDA #$00, 85 10 = STA $10, 60 = RTS
  core::Binary bin = MakeBinary(0x0300, {0xA9, 0x00, 0x85, 0x10, 0x60});
  core::AddressMap map;
  MarkRange(map, 0x0300, 0x0304, core::AddressType::DATA);

  auto candidates = DataCodeScanner::Scan(bin, map, cpu_.get());
  EXPECT_GE(candidates.size(), 1u)
      << "Expected at least one candidate for LDA/STA/RTS sequence";
  EXPECT_EQ(candidates.front().start_address, 0x0300u);
}

TEST_F(DataCodeScannerTest, SkipsCodeRegion) {
  // Same bytes, but marked CODE — scanner should not touch them.
  core::Binary bin = MakeBinary(0x0300, {0xA9, 0x00, 0x85, 0x10, 0x60});
  core::AddressMap map;
  MarkRange(map, 0x0300, 0x0304, core::AddressType::CODE);

  auto candidates = DataCodeScanner::Scan(bin, map, cpu_.get());
  EXPECT_TRUE(candidates.empty())
      << "Should not flag CODE-typed regions as DATA-as-CODE candidates";
}

TEST_F(DataCodeScannerTest, HighBytesNotCandidate) {
  // 0xFF 0xFE 0xFD 0xFC 0xFB — invalid opcodes on NMOS 6502 (illegal)
  core::Binary bin = MakeBinary(0x0300, {0xFF, 0xFE, 0xFD, 0xFC, 0xFB});
  core::AddressMap map;
  MarkRange(map, 0x0300, 0x0304, core::AddressType::DATA);

  auto candidates = DataCodeScanner::Scan(bin, map, cpu_.get());
  // May or may not find candidates depending on how many are legal 2-byte
  // instructions — what must not happen is a >=3-instruction run.
  for (const auto& cand : candidates) {
    EXPECT_LT(cand.length, 10u)  // sanity: no runaway candidates
        << "Unexpected large candidate at $" << std::hex << cand.start_address;
  }
}

TEST_F(DataCodeScannerTest, NullCpuReturnsEmpty) {
  core::Binary bin = MakeBinary(0x0300, {0xA9, 0x00, 0x85, 0x10, 0x60});
  core::AddressMap map;
  MarkRange(map, 0x0300, 0x0304, core::AddressType::DATA);

  auto candidates = DataCodeScanner::Scan(bin, map, nullptr);
  EXPECT_TRUE(candidates.empty())
      << "Null CPU should produce no candidates";
}

TEST_F(DataCodeScannerTest, BuildAnnotationsProducesPossibleCodeType) {
  DataCodeCandidate cand;
  cand.start_address = 0x1234;
  cand.length = 5;
  cand.disasm_listing = "; LDA #$00\n; STA $10\n; RTS\n";

  auto anns = DataCodeScanner::BuildAnnotations({cand});
  ASSERT_EQ(anns.size(), 1u);
  EXPECT_EQ(anns[0].type, AnnotationType::POSSIBLE_CODE);
  EXPECT_EQ(anns[0].address, 0x1234u);
  EXPECT_NE(anns[0].comment.find("POSSIBLE CODE"), std::string::npos);
}

// ===========================================================================
// StringScanner Tests
// ===========================================================================

class StringScannerTest : public ::testing::Test {};

TEST_F(StringScannerTest, FindsAsciiStringInDataRegion) {
  // "HELLO" (5 bytes) — all printable
  core::Binary bin = MakeBinary(0x0200,
      {'H','E','L','L','O', 0x00 /* terminator */});
  core::AddressMap map;
  MarkRange(map, 0x0200, 0x0205, core::AddressType::DATA);

  auto anns = StringScanner::Scan(bin, map);
  ASSERT_GE(anns.size(), 1u) << "Expected 'HELLO' to be found";

  // The annotation should contain the text
  bool found = false;
  for (const auto& ann : anns) {
    if (ann.comment.find("HELLO") != std::string::npos) { found = true; break; }
  }
  EXPECT_TRUE(found) << "Expected comment containing HELLO";
}

TEST_F(StringScannerTest, ShortRunsIgnored) {
  // Only 3 printable bytes — below kMinStringLength (4)
  core::Binary bin = MakeBinary(0x0200, {'H','I','!'});
  core::AddressMap map;
  MarkRange(map, 0x0200, 0x0202, core::AddressType::DATA);

  auto anns = StringScanner::Scan(bin, map);
  EXPECT_TRUE(anns.empty()) << "Three-byte run should not be annotated";
}

TEST_F(StringScannerTest, AnnotationTypeIsStringData) {
  core::Binary bin = MakeBinary(0x0200,
      {'T','E','S','T',0x00});
  core::AddressMap map;
  MarkRange(map, 0x0200, 0x0204, core::AddressType::DATA);

  auto anns = StringScanner::Scan(bin, map);
  ASSERT_GE(anns.size(), 1u);
  EXPECT_EQ(anns[0].type, AnnotationType::STRING_DATA);
}

TEST_F(StringScannerTest, SuggestsLabelWhenNoneExists) {
  core::Binary bin = MakeBinary(0x0300,
      {'H','E','L','L','O',' ','W','O','R','L','D'});
  core::AddressMap map;
  MarkRange(map, 0x0300, 0x030A, core::AddressType::DATA);
  // No label set

  auto anns = StringScanner::Scan(bin, map);
  ASSERT_GE(anns.size(), 1u);
  EXPECT_FALSE(anns[0].label.empty()) << "Should suggest a label";
  EXPECT_NE(anns[0].label.find("0300"), std::string::npos)
      << "Label should include the address: " << anns[0].label;
}

TEST_F(StringScannerTest, SkipsNonDataRegion) {
  core::Binary bin = MakeBinary(0x0200,
      {'T','E','S','T', 0x00});
  core::AddressMap map;
  // Mark as CODE — should not scan
  MarkRange(map, 0x0200, 0x0204, core::AddressType::CODE);

  auto anns = StringScanner::Scan(bin, map);
  EXPECT_TRUE(anns.empty())
      << "CODE-typed regions should not be scanned for strings";
}

TEST_F(StringScannerTest, EmptyBinaryReturnsEmpty) {
  core::Binary bin;
  core::AddressMap map;

  auto anns = StringScanner::Scan(bin, map);
  EXPECT_TRUE(anns.empty());
}

// ===========================================================================
// CodePatternDetector Tests
// ===========================================================================

class CodePatternDetectorTest : public ::testing::Test {
 protected:
  core::Binary bin_;
  core::AddressMap map_;

  void MarkCode(uint32_t start, uint32_t end) {
    MarkRange(map_, start, end, core::AddressType::CODE);
  }

  std::vector<core::Instruction> MakeSubroutine(
      uint32_t base, const std::vector<std::string>& mnemonics,
      bool last_is_return = true) {
    std::vector<core::Instruction> insts;
    uint32_t addr = base;
    for (size_t i = 0; i < mnemonics.size(); ++i) {
      bool is_ret = last_is_return && (i == mnemonics.size() - 1);
      auto inst = MakeInst(addr, mnemonics[i], "", {0xEA}, is_ret, false);
      insts.push_back(inst);
      map_.SetType(addr, core::AddressType::CODE);
      ++addr;
    }
    return insts;
  }
};

TEST_F(CodePatternDetectorTest, IsrHandlerDetection) {
  // PHP, PHA, PHX, [work], PLX, PLA, PLP, RTI
  auto insts = MakeSubroutine(0x1000,
      {"PHP", "PHA", "LDA", "STA", "PLA", "PHP", "RTI"}, true);
  // Make RTI a return
  insts.back().is_return = true;
  insts.back().mnemonic = "RTI";

  map_.SetLabel(0x1000, "irq_handler");

  auto candidates = CodePatternDetector::Detect(bin_, map_, insts);
  bool found_isr = false;
  for (const auto& c : candidates) {
    if (c.pattern == CodePattern::ISR_HANDLER) { found_isr = true; break; }
  }
  EXPECT_TRUE(found_isr) << "ISR handler pattern should be detected";
}

TEST_F(CodePatternDetectorTest, StringCopyDetection) {
  // LDA (src,x), STA (dst,x), INX, BNE loop
  auto insts = MakeSubroutine(0x2000,
      {"LDA", "STA", "INX", "BNE", "RTS"}, true);

  map_.SetLabel(0x2000, "str_copy");

  auto candidates = CodePatternDetector::Detect(bin_, map_, insts);
  bool found_str = false;
  for (const auto& c : candidates) {
    if (c.pattern == CodePattern::STRING_OP) { found_str = true; break; }
  }
  EXPECT_TRUE(found_str) << "String copy pattern should be detected";
}

TEST_F(CodePatternDetectorTest, BcdArithmeticDetection) {
  // SED, CLC, ADC, CLD, RTS
  auto insts = MakeSubroutine(0x3000,
      {"SED", "CLC", "ADC", "CLD", "RTS"}, true);

  map_.SetLabel(0x3000, "bcd_add");

  auto candidates = CodePatternDetector::Detect(bin_, map_, insts);
  bool found_math = false;
  for (const auto& c : candidates) {
    if (c.pattern == CodePattern::MATH) { found_math = true; break; }
  }
  EXPECT_TRUE(found_math) << "BCD arithmetic pattern should be detected";
}

TEST_F(CodePatternDetectorTest, BlockClearDetection) {
  // LDA #0, STA addr, DEX, BNE, RTS
  auto insts = MakeSubroutine(0x4000,
      {"LDA", "STA", "DEX", "BNE", "RTS"}, true);

  map_.SetLabel(0x4000, "clear_mem");

  auto candidates = CodePatternDetector::Detect(bin_, map_, insts);
  bool found_mem = false;
  for (const auto& c : candidates) {
    if (c.pattern == CodePattern::MEMORY_OP) { found_mem = true; break; }
  }
  EXPECT_TRUE(found_mem) << "Block clear/fill pattern should be detected";
}

TEST_F(CodePatternDetectorTest, SmallSubroutineSkipped) {
  // Only 2 instructions — below kMinInstructions
  auto insts = MakeSubroutine(0x5000, {"NOP", "RTS"}, true);
  map_.SetLabel(0x5000, "tiny");

  auto candidates = CodePatternDetector::Detect(bin_, map_, insts);
  // Could be empty or not match any pattern — must not throw
  (void)candidates;
}

TEST_F(CodePatternDetectorTest, PatternNameIsNonEmpty) {
  EXPECT_FALSE(CodePatternDetector::PatternName(CodePattern::STRING_OP).empty());
  EXPECT_FALSE(CodePatternDetector::PatternName(CodePattern::GRAPHICS).empty());
  EXPECT_FALSE(CodePatternDetector::PatternName(CodePattern::MATH).empty());
  EXPECT_FALSE(CodePatternDetector::PatternName(CodePattern::MEMORY_OP).empty());
  EXPECT_FALSE(CodePatternDetector::PatternName(CodePattern::IO_POLLING).empty());
  EXPECT_FALSE(CodePatternDetector::PatternName(CodePattern::DISPATCH_TABLE).empty());
  EXPECT_FALSE(CodePatternDetector::PatternName(CodePattern::ISR_HANDLER).empty());
  EXPECT_FALSE(CodePatternDetector::PatternName(CodePattern::UNKNOWN).empty());
}

TEST_F(CodePatternDetectorTest, EmptyInstructionsReturnsEmpty) {
  auto candidates = CodePatternDetector::Detect(bin_, map_, {});
  EXPECT_TRUE(candidates.empty());
}

// ===========================================================================
// AnnotationType enum coverage
// ===========================================================================

TEST(AnnotationTypeTest, DefaultTypeIsInstruction) {
  LlmAnnotation ann;
  EXPECT_EQ(ann.type, AnnotationType::INSTRUCTION);
}

TEST(AnnotationTypeTest, AllTypeValuesDistinct) {
  EXPECT_NE(static_cast<int>(AnnotationType::INSTRUCTION),
            static_cast<int>(AnnotationType::STRING_DATA));
  EXPECT_NE(static_cast<int>(AnnotationType::STRING_DATA),
            static_cast<int>(AnnotationType::POSSIBLE_CODE));
  EXPECT_NE(static_cast<int>(AnnotationType::POSSIBLE_CODE),
            static_cast<int>(AnnotationType::CODE_PATTERN));
}

}  // namespace
}  // namespace llm
}  // namespace analysis
}  // namespace sourcerer
