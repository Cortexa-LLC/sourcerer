// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "analysis/xref_builder.h"

#include <gtest/gtest.h>

namespace sourcerer {
namespace analysis {
namespace {

// Test fixture for XrefBuilder tests
class XrefBuilderTest : public ::testing::Test {
 protected:
  void SetUp() override {
    address_map_ = std::make_unique<core::AddressMap>();
    builder_ = std::make_unique<XrefBuilder>(address_map_.get());
  }

  // Helper: Create a test instruction
  core::Instruction MakeInstruction(uint32_t address, const std::string& mnemonic,
                                    uint32_t target = 0, bool is_branch = false,
                                    bool is_jump = false, bool is_call = false) {
    core::Instruction inst;
    inst.address = address;
    inst.mnemonic = mnemonic;
    inst.target_address = target;
    inst.is_branch = is_branch;
    inst.is_jump = is_jump;
    inst.is_call = is_call;
    inst.bytes = {0xEA};  // Dummy byte
    return inst;
  }

  std::unique_ptr<core::AddressMap> address_map_;
  std::unique_ptr<XrefBuilder> builder_;
};

// Test building xrefs from single instruction
TEST_F(XrefBuilderTest, SingleXref) {
  std::vector<core::Instruction> instructions;
  instructions.push_back(MakeInstruction(0x8000, "JSR", 0x8010, false, false, true));

  builder_->BuildXrefs(instructions);

  EXPECT_TRUE(address_map_->HasXrefs(0x8010));
  std::vector<uint32_t> xrefs = address_map_->GetXrefs(0x8010);
  ASSERT_EQ(xrefs.size(), 1);
  EXPECT_EQ(xrefs[0], 0x8000);
}

// Test building xrefs from multiple instructions
TEST_F(XrefBuilderTest, MultipleXrefs) {
  std::vector<core::Instruction> instructions;
  instructions.push_back(MakeInstruction(0x8000, "JSR", 0x8010, false, false, true));
  instructions.push_back(MakeInstruction(0x8020, "JSR", 0x8010, false, false, true));
  instructions.push_back(MakeInstruction(0x8030, "JMP", 0x8010, false, true, false));

  builder_->BuildXrefs(instructions);

  EXPECT_TRUE(address_map_->HasXrefs(0x8010));
  std::vector<uint32_t> xrefs = address_map_->GetXrefs(0x8010);
  ASSERT_EQ(xrefs.size(), 3);
  // Check that all sources are present
  EXPECT_TRUE(std::find(xrefs.begin(), xrefs.end(), 0x8000) != xrefs.end());
  EXPECT_TRUE(std::find(xrefs.begin(), xrefs.end(), 0x8020) != xrefs.end());
  EXPECT_TRUE(std::find(xrefs.begin(), xrefs.end(), 0x8030) != xrefs.end());
}

// Test branch instruction xrefs
TEST_F(XrefBuilderTest, BranchXref) {
  std::vector<core::Instruction> instructions;
  instructions.push_back(MakeInstruction(0x8000, "BNE", 0x8010, true, false, false));

  builder_->BuildXrefs(instructions);

  EXPECT_TRUE(address_map_->HasXrefs(0x8010));
  std::vector<uint32_t> xrefs = address_map_->GetXrefs(0x8010);
  ASSERT_EQ(xrefs.size(), 1);
  EXPECT_EQ(xrefs[0], 0x8000);
}

// Test instructions without targets don't create xrefs
TEST_F(XrefBuilderTest, NoTargetNoXref) {
  std::vector<core::Instruction> instructions;
  instructions.push_back(MakeInstruction(0x8000, "LDA", 0, false, false, false));
  instructions.push_back(MakeInstruction(0x8002, "NOP", 0, false, false, false));

  builder_->BuildXrefs(instructions);

  // No xrefs should be created
  EXPECT_FALSE(address_map_->HasXrefs(0x8000));
  EXPECT_FALSE(address_map_->HasXrefs(0x8002));
}

// Test GenerateXrefComment for single xref
TEST_F(XrefBuilderTest, GenerateXrefCommentSingle) {
  address_map_->AddXref(0x8010, 0x8000);

  std::string comment = builder_->GenerateXrefComment(0x8010);

  EXPECT_FALSE(comment.empty());
  EXPECT_TRUE(comment.find("8000") != std::string::npos);
  EXPECT_TRUE(comment.find("Referenced from") != std::string::npos);
}

// Test GenerateXrefComment for multiple xrefs
TEST_F(XrefBuilderTest, GenerateXrefCommentMultiple) {
  address_map_->AddXref(0x8010, 0x8000);
  address_map_->AddXref(0x8010, 0x8020);
  address_map_->AddXref(0x8010, 0x8030);

  std::string comment = builder_->GenerateXrefComment(0x8010);

  EXPECT_FALSE(comment.empty());
  EXPECT_TRUE(comment.find("8000") != std::string::npos);
  EXPECT_TRUE(comment.find("8020") != std::string::npos);
  EXPECT_TRUE(comment.find("8030") != std::string::npos);
}

// Test GenerateXrefComment for no xrefs
TEST_F(XrefBuilderTest, GenerateXrefCommentEmpty) {
  std::string comment = builder_->GenerateXrefComment(0x8010);

  EXPECT_TRUE(comment.empty());
}

// Test AddXrefComments
TEST_F(XrefBuilderTest, AddXrefComments) {
  address_map_->AddXref(0x8010, 0x8000);
  address_map_->AddXref(0x8020, 0x8000);

  builder_->AddXrefComments();

  // Comments should be added for addresses with xrefs
  EXPECT_TRUE(address_map_->HasComment(0x8010));
  EXPECT_TRUE(address_map_->HasComment(0x8020));

  std::string comment1 = address_map_->GetComment(0x8010);
  std::string comment2 = address_map_->GetComment(0x8020);

  EXPECT_FALSE(comment1.empty());
  EXPECT_FALSE(comment2.empty());
  EXPECT_TRUE(comment1.find("8000") != std::string::npos);
  EXPECT_TRUE(comment2.find("8000") != std::string::npos);
}

// Test that AddXrefComments preserves existing comments
TEST_F(XrefBuilderTest, PreservesExistingComments) {
  address_map_->SetComment(0x8010, "My comment");
  address_map_->AddXref(0x8010, 0x8000);

  builder_->AddXrefComments();

  std::string comment = address_map_->GetComment(0x8010);

  // Should have both the original comment and xref info
  EXPECT_TRUE(comment.find("My comment") != std::string::npos);
  EXPECT_TRUE(comment.find("8000") != std::string::npos);
}

// Test xrefs sorted in output
TEST_F(XrefBuilderTest, SortedXrefs) {
  address_map_->AddXref(0x8010, 0x8030);
  address_map_->AddXref(0x8010, 0x8000);
  address_map_->AddXref(0x8010, 0x8020);

  std::string comment = builder_->GenerateXrefComment(0x8010);

  // Find positions of addresses in comment
  size_t pos_8000 = comment.find("8000");
  size_t pos_8020 = comment.find("8020");
  size_t pos_8030 = comment.find("8030");

  // Should be sorted (8000 < 8020 < 8030)
  EXPECT_LT(pos_8000, pos_8020);
  EXPECT_LT(pos_8020, pos_8030);
}

// Test maximum xrefs limit
TEST_F(XrefBuilderTest, MaxXrefsLimit) {
  // Add more than MAX_XREFS_IN_COMMENT xrefs
  for (uint32_t i = 0; i < 15; ++i) {
    address_map_->AddXref(0x8010, 0x8000 + i * 0x10);
  }

  std::string comment = builder_->GenerateXrefComment(0x8010);

  EXPECT_FALSE(comment.empty());
  // Comment should indicate there are more xrefs not shown
  // (implementation may use "..." or similar)
}

// Test xrefs from different instruction types
TEST_F(XrefBuilderTest, DifferentInstructionTypes) {
  std::vector<core::Instruction> instructions;

  // JSR (call)
  instructions.push_back(MakeInstruction(0x8000, "JSR", 0x8100, false, false, true));

  // JMP (jump)
  instructions.push_back(MakeInstruction(0x8010, "JMP", 0x8200, false, true, false));

  // BNE (branch)
  instructions.push_back(MakeInstruction(0x8020, "BNE", 0x8030, true, false, false));

  builder_->BuildXrefs(instructions);

  EXPECT_TRUE(address_map_->HasXrefs(0x8100));
  EXPECT_TRUE(address_map_->HasXrefs(0x8200));
  EXPECT_TRUE(address_map_->HasXrefs(0x8030));
}

// Test xrefs to zero page addresses
TEST_F(XrefBuilderTest, ZeroPageXrefs) {
  std::vector<core::Instruction> instructions;
  instructions.push_back(MakeInstruction(0x8000, "JMP", 0x0010, false, true, false));

  builder_->BuildXrefs(instructions);

  EXPECT_TRUE(address_map_->HasXrefs(0x0010));
}

// Test xrefs to high addresses
TEST_F(XrefBuilderTest, HighAddressXrefs) {
  std::vector<core::Instruction> instructions;
  instructions.push_back(MakeInstruction(0x8000, "JSR", 0xFDED, false, false, true));

  builder_->BuildXrefs(instructions);

  EXPECT_TRUE(address_map_->HasXrefs(0xFDED));
}

// Test empty instruction list
TEST_F(XrefBuilderTest, EmptyInstructions) {
  std::vector<core::Instruction> instructions;

  builder_->BuildXrefs(instructions);

  // Should not crash, no xrefs should be created
  EXPECT_FALSE(address_map_->HasXrefs(0x8000));
}

// Test comprehensive scenario
TEST_F(XrefBuilderTest, ComprehensiveScenario) {
  std::vector<core::Instruction> instructions;

  // Main program
  instructions.push_back(MakeInstruction(0x8000, "JSR", 0x8010, false, false, true));
  instructions.push_back(MakeInstruction(0x8003, "JSR", 0x8020, false, false, true));
  instructions.push_back(MakeInstruction(0x8006, "JMP", 0x8030, false, true, false));

  // Subroutine 1
  instructions.push_back(MakeInstruction(0x8010, "BNE", 0x8015, true, false, false));
  instructions.push_back(MakeInstruction(0x8012, "RTS", 0, false, false, false));

  // Subroutine 2
  instructions.push_back(MakeInstruction(0x8020, "JSR", 0x8010, false, false, true));
  instructions.push_back(MakeInstruction(0x8023, "RTS", 0, false, false, false));

  builder_->BuildXrefs(instructions);
  builder_->AddXrefComments();

  // 0x8010 should be referenced from 0x8000 and 0x8020
  EXPECT_TRUE(address_map_->HasXrefs(0x8010));
  std::vector<uint32_t> xrefs_8010 = address_map_->GetXrefs(0x8010);
  EXPECT_EQ(xrefs_8010.size(), 2);

  // 0x8020 should be referenced from 0x8003
  EXPECT_TRUE(address_map_->HasXrefs(0x8020));

  // 0x8030 should be referenced from 0x8006
  EXPECT_TRUE(address_map_->HasXrefs(0x8030));

  // 0x8015 should be referenced from 0x8010 (branch target)
  EXPECT_TRUE(address_map_->HasXrefs(0x8015));

  // All should have comments
  EXPECT_TRUE(address_map_->HasComment(0x8010));
  EXPECT_TRUE(address_map_->HasComment(0x8020));
  EXPECT_TRUE(address_map_->HasComment(0x8030));
  EXPECT_TRUE(address_map_->HasComment(0x8015));
}

}  // namespace
}  // namespace analysis
}  // namespace sourcerer
