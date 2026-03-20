// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

// Unit tests for the LLM analysis plugin layer:
//   - LlmAnalyzer interface (ApplyAnnotations)
//   - LlmAnalyzerRegistry (register, list, has, create)
//   - ChunkBuilder (format and split)
//   - MockLlmAnalyzer (graceful degradation contract)

#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

#include "analysis/llm/chunk_builder.h"
#include "analysis/llm/llm_analyzer.h"
#include "analysis/llm/llm_analyzer_registry.h"
#include "core/address_map.h"
#include "core/instruction.h"

namespace sourcerer {
namespace analysis {
namespace llm {
namespace {

// ---------------------------------------------------------------------------
// Mock LLM analyzer used by tests
// ---------------------------------------------------------------------------
class MockLlmAnalyzer : public LlmAnalyzer {
 public:
  explicit MockLlmAnalyzer(std::vector<LlmAnnotation> response)
      : response_(std::move(response)) {}

  std::string Name() const override { return "mock"; }

  std::vector<LlmAnnotation> Analyze(
      const std::string& /*chunk_context*/,
      const std::vector<core::Instruction>& /*instructions*/) override {
    return response_;
  }

 private:
  std::vector<LlmAnnotation> response_;
};

// Helper: build a minimal instruction
core::Instruction MakeInst(uint32_t addr, const std::string& mnemonic,
                            const std::string& operand = "") {
  core::Instruction inst{};
  inst.address = addr;
  inst.mnemonic = mnemonic;
  inst.operand = operand;
  inst.bytes = {0xA9};  // placeholder
  return inst;
}

// ===========================================================================
// LlmAnalyzer::ApplyAnnotations tests
// ===========================================================================

TEST(LlmAnalyzerTest, ApplyAnnotations_WritesLabelAndComment) {
  core::AddressMap map;
  std::vector<LlmAnnotation> anns = {
      {0x1000, "InitRoutine", "Initialize system state"},
      {0x1003, "LoopTop", ""},
      {0x1006, "", "Check completion flag"},
  };

  LlmAnalyzer::ApplyAnnotations(anns, &map);

  EXPECT_EQ(map.GetLabel(0x1000), std::optional<std::string>("InitRoutine"));
  EXPECT_EQ(map.GetComment(0x1000),
            std::optional<std::string>("Initialize system state"));
  EXPECT_EQ(map.GetLabel(0x1003), std::optional<std::string>("LoopTop"));
  EXPECT_FALSE(map.GetComment(0x1003).has_value());
  EXPECT_FALSE(map.GetLabel(0x1006).has_value());
  EXPECT_EQ(map.GetComment(0x1006),
            std::optional<std::string>("Check completion flag"));
}

TEST(LlmAnalyzerTest, ApplyAnnotations_NullMapIsNoOp) {
  // Should not crash
  std::vector<LlmAnnotation> anns = {{0x1000, "Label", "Comment"}};
  EXPECT_NO_THROW(LlmAnalyzer::ApplyAnnotations(anns, nullptr));
}

TEST(LlmAnalyzerTest, ApplyAnnotations_EmptyAnnotationsIsNoOp) {
  core::AddressMap map;
  map.SetLabel(0x2000, "Existing");

  LlmAnalyzer::ApplyAnnotations({}, &map);

  EXPECT_EQ(map.GetLabel(0x2000), std::optional<std::string>("Existing"));
}

TEST(LlmAnalyzerTest, ApplyAnnotations_OverwritesExistingLabel) {
  core::AddressMap map;
  map.SetLabel(0x3000, "OldLabel");

  std::vector<LlmAnnotation> anns = {{0x3000, "NewLabel", ""}};
  LlmAnalyzer::ApplyAnnotations(anns, &map);

  EXPECT_EQ(map.GetLabel(0x3000), std::optional<std::string>("NewLabel"));
}

// ===========================================================================
// LlmAnalyzerRegistry tests
// ===========================================================================

TEST(LlmAnalyzerRegistryTest, HasClaude) {
  auto& reg = LlmAnalyzerRegistry::Instance();
  EXPECT_TRUE(reg.Has("claude"));
}

TEST(LlmAnalyzerRegistryTest, HasUnknownProviderReturnsFalse) {
  auto& reg = LlmAnalyzerRegistry::Instance();
  EXPECT_FALSE(reg.Has("nonexistent_provider_xyz"));
}

TEST(LlmAnalyzerRegistryTest, CreateClaudeReturnsNonNull) {
  auto& reg = LlmAnalyzerRegistry::Instance();
  auto analyzer = reg.Create("claude");
  ASSERT_NE(analyzer, nullptr);
  EXPECT_EQ(analyzer->Name(), "claude");
}

TEST(LlmAnalyzerRegistryTest, CreateUnknownReturnsNull) {
  auto& reg = LlmAnalyzerRegistry::Instance();
  auto analyzer = reg.Create("not_a_real_provider");
  EXPECT_EQ(analyzer, nullptr);
}

TEST(LlmAnalyzerRegistryTest, RegisterCustomProvider) {
  auto& reg = LlmAnalyzerRegistry::Instance();
  reg.Register("mock_test_provider", []() -> std::unique_ptr<LlmAnalyzer> {
    return std::make_unique<MockLlmAnalyzer>(std::vector<LlmAnnotation>{});
  });

  EXPECT_TRUE(reg.Has("mock_test_provider"));
  auto analyzer = reg.Create("mock_test_provider");
  ASSERT_NE(analyzer, nullptr);
  EXPECT_EQ(analyzer->Name(), "mock");
}

TEST(LlmAnalyzerRegistryTest, ListProvidersContainsClaude) {
  auto& reg = LlmAnalyzerRegistry::Instance();
  auto providers = reg.ListProviders();
  bool found = false;
  for (const auto& p : providers) {
    if (p == "claude") found = true;
  }
  EXPECT_TRUE(found);
}

// ===========================================================================
// ChunkBuilder tests
// ===========================================================================

TEST(ChunkBuilderTest, SplitReturnsCorrectChunkCount) {
  std::vector<core::Instruction> insts;
  for (int i = 0; i < 250; ++i) {
    insts.push_back(MakeInst(0x1000 + i, "NOP"));
  }

  ChunkBuilder builder(100);
  auto chunks = builder.Split(insts);

  // 250 / 100 = 3 chunks (100, 100, 50)
  ASSERT_EQ(chunks.size(), 3u);
  EXPECT_EQ(chunks[0].size(), 100u);
  EXPECT_EQ(chunks[1].size(), 100u);
  EXPECT_EQ(chunks[2].size(), 50u);
}

TEST(ChunkBuilderTest, SplitEmptyInstructionsReturnsNoChunks) {
  ChunkBuilder builder(100);
  auto chunks = builder.Split({});
  EXPECT_TRUE(chunks.empty());
}

TEST(ChunkBuilderTest, SplitSmallerThanChunkSizeGivesOneChunk) {
  std::vector<core::Instruction> insts;
  for (int i = 0; i < 5; ++i) {
    insts.push_back(MakeInst(0x2000 + i, "LDA", "#$00"));
  }

  ChunkBuilder builder(100);
  auto chunks = builder.Split(insts);
  ASSERT_EQ(chunks.size(), 1u);
  EXPECT_EQ(chunks[0].size(), 5u);
}

TEST(ChunkBuilderTest, FormatChunkContainsAddressAndMnemonic) {
  core::AddressMap map;
  std::vector<core::Instruction> insts = {
      MakeInst(0x1000, "LDA", "#$FF"),
      MakeInst(0x1002, "STA", "$0200"),
  };
  insts[0].bytes = {0xA9, 0xFF};
  insts[1].bytes = {0x8D, 0x00, 0x02};

  std::string text = ChunkBuilder::FormatChunk(insts, map);

  EXPECT_NE(text.find("$1000"), std::string::npos);
  EXPECT_NE(text.find("LDA"), std::string::npos);
  EXPECT_NE(text.find("#$FF"), std::string::npos);
  EXPECT_NE(text.find("$1002"), std::string::npos);
  EXPECT_NE(text.find("STA"), std::string::npos);
}

TEST(ChunkBuilderTest, FormatChunkIncludesExistingLabel) {
  core::AddressMap map;
  map.SetLabel(0x1000, "MyLabel");

  std::vector<core::Instruction> insts = {MakeInst(0x1000, "RTS")};
  std::string text = ChunkBuilder::FormatChunk(insts, map);

  EXPECT_NE(text.find("MyLabel"), std::string::npos);
}

TEST(ChunkBuilderTest, FormatChunkIncludesExistingComment) {
  core::AddressMap map;
  map.SetComment(0x1000, "existing comment");

  std::vector<core::Instruction> insts = {MakeInst(0x1000, "RTS")};
  std::string text = ChunkBuilder::FormatChunk(insts, map);

  EXPECT_NE(text.find("existing comment"), std::string::npos);
}

// ===========================================================================
// MockLlmAnalyzer integration: graceful degradation contract
// ===========================================================================

TEST(MockLlmAnalyzerTest, EmptyResponseIsGraceful) {
  MockLlmAnalyzer analyzer({});
  core::AddressMap map;
  map.SetLabel(0x1000, "OriginalLabel");

  auto anns = analyzer.Analyze("some context", {MakeInst(0x1000, "NOP")});
  LlmAnalyzer::ApplyAnnotations(anns, &map);

  // Original label must be preserved when LLM returns nothing
  EXPECT_EQ(map.GetLabel(0x1000), std::optional<std::string>("OriginalLabel"));
}

TEST(MockLlmAnalyzerTest, AnnotationsAreApplied) {
  std::vector<LlmAnnotation> response = {
      {0x1000, "BetterLabel", "Does the initialization"},
  };
  MockLlmAnalyzer analyzer(response);
  core::AddressMap map;
  map.SetLabel(0x1000, "OriginalLabel");

  auto anns = analyzer.Analyze("some context", {MakeInst(0x1000, "NOP")});
  LlmAnalyzer::ApplyAnnotations(anns, &map);

  EXPECT_EQ(map.GetLabel(0x1000), std::optional<std::string>("BetterLabel"));
  EXPECT_EQ(map.GetComment(0x1000),
            std::optional<std::string>("Does the initialization"));
}

}  // namespace
}  // namespace llm
}  // namespace analysis
}  // namespace sourcerer
