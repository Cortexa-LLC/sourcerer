// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "core/address_map.h"

#include <gtest/gtest.h>

namespace sourcerer {
namespace core {
namespace {

// Test fixture for AddressMap class
class AddressMapTest : public ::testing::Test {
 protected:
  void SetUp() override {
    addr_map_ = std::make_unique<AddressMap>();
  }

  std::unique_ptr<AddressMap> addr_map_;
};

// Test default state
TEST_F(AddressMapTest, DefaultState) {
  // All addresses start as UNKNOWN
  EXPECT_EQ(addr_map_->GetType(0x8000), AddressType::UNKNOWN);
  EXPECT_FALSE(addr_map_->IsCode(0x8000));
  EXPECT_FALSE(addr_map_->IsData(0x8000));
  EXPECT_FALSE(addr_map_->HasLabel(0x8000));
  EXPECT_FALSE(addr_map_->HasComment(0x8000));
  EXPECT_FALSE(addr_map_->HasXrefs(0x8000));
}

// Test type tracking
TEST_F(AddressMapTest, TypeTracking) {
  addr_map_->SetType(0x8000, AddressType::CODE);
  EXPECT_EQ(addr_map_->GetType(0x8000), AddressType::CODE);
  EXPECT_TRUE(addr_map_->IsCode(0x8000));
  EXPECT_FALSE(addr_map_->IsData(0x8000));

  addr_map_->SetType(0x9000, AddressType::DATA);
  EXPECT_EQ(addr_map_->GetType(0x9000), AddressType::DATA);
  EXPECT_FALSE(addr_map_->IsCode(0x9000));
  EXPECT_TRUE(addr_map_->IsData(0x9000));

  addr_map_->SetType(0xA000, AddressType::INLINE_DATA);
  EXPECT_EQ(addr_map_->GetType(0xA000), AddressType::INLINE_DATA);
  EXPECT_FALSE(addr_map_->IsCode(0xA000));
  EXPECT_TRUE(addr_map_->IsData(0xA000));
}

// Test hint types
TEST_F(AddressMapTest, HintTypes) {
  addr_map_->SetType(0x8000, AddressType::HINT_CODE);
  EXPECT_EQ(addr_map_->GetType(0x8000), AddressType::HINT_CODE);
  EXPECT_TRUE(addr_map_->IsCode(0x8000));

  addr_map_->SetType(0x9000, AddressType::HINT_DATA);
  EXPECT_EQ(addr_map_->GetType(0x9000), AddressType::HINT_DATA);
  EXPECT_TRUE(addr_map_->IsData(0x9000));
}

// Test label management
TEST_F(AddressMapTest, LabelManagement) {
  // Set label
  addr_map_->SetLabel(0x8000, "START");
  EXPECT_TRUE(addr_map_->HasLabel(0x8000));
  EXPECT_EQ(addr_map_->GetLabel(0x8000), "START");

  // Update label
  addr_map_->SetLabel(0x8000, "MAIN");
  EXPECT_EQ(addr_map_->GetLabel(0x8000), "MAIN");

  // Multiple labels
  addr_map_->SetLabel(0x8010, "SUB_8010");
  addr_map_->SetLabel(0x8020, "LOOP");
  EXPECT_TRUE(addr_map_->HasLabel(0x8010));
  EXPECT_TRUE(addr_map_->HasLabel(0x8020));
  EXPECT_EQ(addr_map_->GetLabel(0x8010), "SUB_8010");
  EXPECT_EQ(addr_map_->GetLabel(0x8020), "LOOP");
}

// Test GetAllLabels
TEST_F(AddressMapTest, GetAllLabels) {
  addr_map_->SetLabel(0x8000, "START");
  addr_map_->SetLabel(0x8010, "SUB_8010");
  addr_map_->SetLabel(0x8020, "LOOP");

  const auto& labels = addr_map_->GetAllLabels();
  EXPECT_EQ(labels.size(), 3);
  EXPECT_EQ(labels.at(0x8000), "START");
  EXPECT_EQ(labels.at(0x8010), "SUB_8010");
  EXPECT_EQ(labels.at(0x8020), "LOOP");
}

// Test comment management
TEST_F(AddressMapTest, CommentManagement) {
  // Set comment
  addr_map_->SetComment(0x8000, "Entry point");
  EXPECT_TRUE(addr_map_->HasComment(0x8000));
  EXPECT_EQ(addr_map_->GetComment(0x8000), "Entry point");

  // Update comment
  addr_map_->SetComment(0x8000, "Program start");
  EXPECT_EQ(addr_map_->GetComment(0x8000), "Program start");

  // Multiple comments
  addr_map_->SetComment(0x8010, "Initialize");
  addr_map_->SetComment(0x8020, "Main loop");
  EXPECT_TRUE(addr_map_->HasComment(0x8010));
  EXPECT_TRUE(addr_map_->HasComment(0x8020));
}

// Test append comment
TEST_F(AddressMapTest, AppendComment) {
  addr_map_->SetComment(0x8000, "Entry point");
  addr_map_->AppendComment(0x8000, " - Start of program");
  EXPECT_EQ(addr_map_->GetComment(0x8000), "Entry point - Start of program");

  // Append to non-existent comment
  addr_map_->AppendComment(0x8010, "New comment");
  EXPECT_EQ(addr_map_->GetComment(0x8010), "New comment");
}

// Test cross-reference tracking
TEST_F(AddressMapTest, CrossReferences) {
  // Add single xref
  addr_map_->AddXref(0x8010, 0x8000);  // 8000 references 8010
  EXPECT_TRUE(addr_map_->HasXrefs(0x8010));

  std::vector<uint32_t> xrefs = addr_map_->GetXrefs(0x8010);
  EXPECT_EQ(xrefs.size(), 1);
  EXPECT_EQ(xrefs[0], 0x8000);

  // Add multiple xrefs to same target
  addr_map_->AddXref(0x8010, 0x8020);  // 8020 references 8010
  addr_map_->AddXref(0x8010, 0x8030);  // 8030 references 8010

  xrefs = addr_map_->GetXrefs(0x8010);
  EXPECT_EQ(xrefs.size(), 3);
  EXPECT_TRUE(std::find(xrefs.begin(), xrefs.end(), 0x8000) != xrefs.end());
  EXPECT_TRUE(std::find(xrefs.begin(), xrefs.end(), 0x8020) != xrefs.end());
  EXPECT_TRUE(std::find(xrefs.begin(), xrefs.end(), 0x8030) != xrefs.end());
}

// Test xrefs for multiple targets
TEST_F(AddressMapTest, MultipleTargetXrefs) {
  addr_map_->AddXref(0x8010, 0x8000);
  addr_map_->AddXref(0x8020, 0x8000);
  addr_map_->AddXref(0x8030, 0x8010);

  EXPECT_TRUE(addr_map_->HasXrefs(0x8010));
  EXPECT_TRUE(addr_map_->HasXrefs(0x8020));
  EXPECT_TRUE(addr_map_->HasXrefs(0x8030));

  EXPECT_EQ(addr_map_->GetXrefs(0x8010).size(), 1);
  EXPECT_EQ(addr_map_->GetXrefs(0x8020).size(), 1);
  EXPECT_EQ(addr_map_->GetXrefs(0x8030).size(), 1);
}

// Test GetAllXrefs
TEST_F(AddressMapTest, GetAllXrefs) {
  addr_map_->AddXref(0x8010, 0x8000);
  addr_map_->AddXref(0x8010, 0x8020);
  addr_map_->AddXref(0x8020, 0x8000);

  const auto& xrefs = addr_map_->GetAllXrefs();
  EXPECT_EQ(xrefs.count(0x8010), 2);
  EXPECT_EQ(xrefs.count(0x8020), 1);
}

// Test entry points
TEST_F(AddressMapTest, EntryPoints) {
  EXPECT_TRUE(addr_map_->GetEntryPoints().empty());

  addr_map_->AddEntryPoint(0x8000);
  EXPECT_EQ(addr_map_->GetEntryPoints().size(), 1);
  EXPECT_TRUE(addr_map_->GetEntryPoints().count(0x8000) > 0);

  addr_map_->AddEntryPoint(0x9000);
  addr_map_->AddEntryPoint(0xA000);
  EXPECT_EQ(addr_map_->GetEntryPoints().size(), 3);
  EXPECT_TRUE(addr_map_->GetEntryPoints().count(0x9000) > 0);
  EXPECT_TRUE(addr_map_->GetEntryPoints().count(0xA000) > 0);
}

// Test duplicate entry points
TEST_F(AddressMapTest, DuplicateEntryPoints) {
  addr_map_->AddEntryPoint(0x8000);
  addr_map_->AddEntryPoint(0x8000);  // Duplicate
  EXPECT_EQ(addr_map_->GetEntryPoints().size(), 1);
}

// Test Clear method
TEST_F(AddressMapTest, Clear) {
  // Set up various data
  addr_map_->SetType(0x8000, AddressType::CODE);
  addr_map_->SetLabel(0x8000, "START");
  addr_map_->SetComment(0x8000, "Entry point");
  addr_map_->AddXref(0x8010, 0x8000);
  addr_map_->AddEntryPoint(0x8000);

  // Verify data exists
  EXPECT_TRUE(addr_map_->IsCode(0x8000));
  EXPECT_TRUE(addr_map_->HasLabel(0x8000));
  EXPECT_TRUE(addr_map_->HasComment(0x8000));
  EXPECT_TRUE(addr_map_->HasXrefs(0x8010));
  EXPECT_FALSE(addr_map_->GetEntryPoints().empty());

  // Clear everything
  addr_map_->Clear();

  // Verify all data cleared
  EXPECT_EQ(addr_map_->GetType(0x8000), AddressType::UNKNOWN);
  EXPECT_FALSE(addr_map_->HasLabel(0x8000));
  EXPECT_FALSE(addr_map_->HasComment(0x8000));
  EXPECT_FALSE(addr_map_->HasXrefs(0x8010));
  EXPECT_TRUE(addr_map_->GetEntryPoints().empty());
}

// Test type override
TEST_F(AddressMapTest, TypeOverride) {
  addr_map_->SetType(0x8000, AddressType::CODE);
  EXPECT_TRUE(addr_map_->IsCode(0x8000));

  // Override with DATA
  addr_map_->SetType(0x8000, AddressType::DATA);
  EXPECT_TRUE(addr_map_->IsData(0x8000));
  EXPECT_FALSE(addr_map_->IsCode(0x8000));

  // Override with hint
  addr_map_->SetType(0x8000, AddressType::HINT_CODE);
  EXPECT_TRUE(addr_map_->IsCode(0x8000));
  EXPECT_FALSE(addr_map_->IsData(0x8000));
}

// Test address boundaries
TEST_F(AddressMapTest, AddressBoundaries) {
  // Zero page
  addr_map_->SetType(0x00, AddressType::CODE);
  addr_map_->SetLabel(0x00, "ZP_START");
  EXPECT_TRUE(addr_map_->IsCode(0x00));
  EXPECT_EQ(addr_map_->GetLabel(0x00), "ZP_START");

  // High memory (16-bit)
  addr_map_->SetType(0xFFFF, AddressType::CODE);
  addr_map_->SetLabel(0xFFFF, "END");
  EXPECT_TRUE(addr_map_->IsCode(0xFFFF));
  EXPECT_EQ(addr_map_->GetLabel(0xFFFF), "END");

  // 32-bit address (for future 24-bit+ CPUs)
  addr_map_->SetType(0x123456, AddressType::CODE);
  addr_map_->SetLabel(0x123456, "LONG_ADDR");
  EXPECT_TRUE(addr_map_->IsCode(0x123456));
  EXPECT_EQ(addr_map_->GetLabel(0x123456), "LONG_ADDR");
}

// Test empty label/comment retrieval
TEST_F(AddressMapTest, EmptyRetrievals) {
  // Get label for address without label
  EXPECT_FALSE(addr_map_->HasLabel(0x8000));
  EXPECT_EQ(addr_map_->GetLabel(0x8000), "");

  // Get comment for address without comment
  EXPECT_FALSE(addr_map_->HasComment(0x8000));
  EXPECT_EQ(addr_map_->GetComment(0x8000), "");

  // Get xrefs for address without xrefs
  EXPECT_FALSE(addr_map_->HasXrefs(0x8000));
  EXPECT_TRUE(addr_map_->GetXrefs(0x8000).empty());
}

// Test inline data type
TEST_F(AddressMapTest, InlineDataType) {
  addr_map_->SetType(0x8000, AddressType::INLINE_DATA);
  EXPECT_EQ(addr_map_->GetType(0x8000), AddressType::INLINE_DATA);
  EXPECT_FALSE(addr_map_->IsCode(0x8000));
  EXPECT_TRUE(addr_map_->IsData(0x8000));
}

// Test comprehensive scenario
TEST_F(AddressMapTest, ComprehensiveScenario) {
  // Simulate a small program analysis

  // Entry point
  addr_map_->AddEntryPoint(0x8000);
  addr_map_->SetType(0x8000, AddressType::CODE);
  addr_map_->SetLabel(0x8000, "START");
  addr_map_->SetComment(0x8000, "Program entry");

  // Subroutine
  addr_map_->SetType(0x8010, AddressType::CODE);
  addr_map_->SetLabel(0x8010, "INIT");
  addr_map_->SetComment(0x8010, "Initialize variables");
  addr_map_->AddXref(0x8010, 0x8003);  // Called from START

  // Data region
  addr_map_->SetType(0x9000, AddressType::DATA);
  addr_map_->SetLabel(0x9000, "DATA_TABLE");
  addr_map_->SetComment(0x9000, "Lookup table");
  addr_map_->AddXref(0x9000, 0x8015);  // Referenced from INIT

  // Verify everything
  EXPECT_EQ(addr_map_->GetEntryPoints().size(), 1);
  EXPECT_TRUE(addr_map_->IsCode(0x8000));
  EXPECT_TRUE(addr_map_->IsCode(0x8010));
  EXPECT_TRUE(addr_map_->IsData(0x9000));
  EXPECT_EQ(addr_map_->GetLabel(0x8000), "START");
  EXPECT_EQ(addr_map_->GetLabel(0x8010), "INIT");
  EXPECT_EQ(addr_map_->GetLabel(0x9000), "DATA_TABLE");
  EXPECT_TRUE(addr_map_->HasXrefs(0x8010));
  EXPECT_TRUE(addr_map_->HasXrefs(0x9000));
}

}  // namespace
}  // namespace core
}  // namespace sourcerer
