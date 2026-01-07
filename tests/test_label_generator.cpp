// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "analysis/label_generator.h"

#include <gtest/gtest.h>

namespace sourcerer {
namespace analysis {
namespace {

// Test fixture for LabelGenerator tests
class LabelGeneratorTest : public ::testing::Test {
 protected:
  void SetUp() override {
    address_map_ = std::make_unique<core::AddressMap>();
  }

  std::unique_ptr<core::AddressMap> address_map_;
};

// Test basic label generation for entry point
TEST_F(LabelGeneratorTest, EntryPointLabel) {
  address_map_->AddEntryPoint(0x8000);

  LabelGenerator generator(address_map_.get());
  std::string label = generator.GenerateLabelForAddress(0x8000);

  EXPECT_FALSE(label.empty());
  EXPECT_TRUE(label == "START" || label == "MAIN" || label.find("ENTRY") != std::string::npos);
}

// Test subroutine label generation
TEST_F(LabelGeneratorTest, SubroutineLabel) {
  // Address 0x8010 is referenced by a JSR (simulated via xref)
  address_map_->SetType(0x8010, core::AddressType::CODE);
  address_map_->AddXref(0x8010, 0x8000);  // Referenced from 0x8000

  LabelGenerator generator(address_map_.get());
  std::string label = generator.GenerateLabelForAddress(0x8010);

  EXPECT_FALSE(label.empty());
  // Should be SUB_xxxx format
  EXPECT_TRUE(label.find("SUB") != std::string::npos || label.find("8010") != std::string::npos);
}

// Test data label generation
TEST_F(LabelGeneratorTest, DataLabel) {
  address_map_->SetType(0x9000, core::AddressType::DATA);

  LabelGenerator generator(address_map_.get());
  std::string label = generator.GenerateLabelForAddress(0x9000);

  EXPECT_FALSE(label.empty());
  // Should be DATA_xxxx format
  EXPECT_TRUE(label.find("DATA") != std::string::npos || label.find("9000") != std::string::npos);
}

// Test zero page label generation
TEST_F(LabelGeneratorTest, ZeroPageLabel) {
  address_map_->SetType(0x0010, core::AddressType::DATA);

  LabelGenerator generator(address_map_.get());
  std::string label = generator.GenerateLabelForAddress(0x0010);

  EXPECT_FALSE(label.empty());
  // Should be ZP_xx format
  EXPECT_TRUE(label.find("ZP") != std::string::npos || label.find("10") != std::string::npos);
}

// Test branch target label generation
TEST_F(LabelGeneratorTest, BranchLabel) {
  address_map_->SetType(0x8020, core::AddressType::CODE);
  address_map_->AddXref(0x8020, 0x8000);  // Referenced from nearby

  LabelGenerator generator(address_map_.get());
  std::string label = generator.GenerateLabelForAddress(0x8020);

  EXPECT_FALSE(label.empty());
  // Should be L_xxxx or similar format
  EXPECT_TRUE(label.find("L") == 0 || label.find("8020") != std::string::npos);
}

// Test that existing labels are not overwritten
TEST_F(LabelGeneratorTest, DoesNotOverwriteExistingLabel) {
  address_map_->SetLabel(0x8000, "MY_LABEL");

  LabelGenerator generator(address_map_.get());
  std::string label = generator.GenerateLabelForAddress(0x8000);

  // May return existing label or empty string - either is acceptable
  // The important thing is that the original label is preserved
  EXPECT_EQ(address_map_->GetLabel(0x8000), "MY_LABEL");
}

// Test generating labels for multiple addresses
TEST_F(LabelGeneratorTest, GenerateMultipleLabels) {
  address_map_->AddEntryPoint(0x8000);
  address_map_->SetType(0x8000, core::AddressType::CODE);
  address_map_->SetType(0x8010, core::AddressType::CODE);
  address_map_->AddXref(0x8010, 0x8000);
  address_map_->SetType(0x9000, core::AddressType::DATA);
  address_map_->AddXref(0x9000, 0x8005);

  LabelGenerator generator(address_map_.get());

  // Generate labels explicitly for each address
  std::string label1 = generator.GenerateLabelForAddress(0x8000);
  std::string label2 = generator.GenerateLabelForAddress(0x8010);
  std::string label3 = generator.GenerateLabelForAddress(0x9000);

  // All addresses should get labels
  EXPECT_FALSE(label1.empty());  // Entry point
  EXPECT_FALSE(label2.empty());  // Xref target
  EXPECT_FALSE(label3.empty());  // Data with xref
}

// Test label uniqueness
TEST_F(LabelGeneratorTest, UniqueLabels) {
  address_map_->SetType(0x8000, core::AddressType::CODE);
  address_map_->AddXref(0x8000, 0x7000);
  address_map_->SetType(0x8010, core::AddressType::CODE);
  address_map_->AddXref(0x8010, 0x7010);

  LabelGenerator generator(address_map_.get());
  std::string label1 = generator.GenerateLabelForAddress(0x8000);
  std::string label2 = generator.GenerateLabelForAddress(0x8010);

  EXPECT_FALSE(label1.empty());
  EXPECT_FALSE(label2.empty());
  EXPECT_NE(label1, label2);  // Labels should be unique
}

// Test with symbol table
TEST_F(LabelGeneratorTest, WithSymbolTable) {
  core::SymbolTable symbol_table;
  symbol_table.AddSymbol(0xC000, "KEYBOARD");
  symbol_table.AddSymbol(0xFDED, "COUT");

  address_map_->SetType(0xC000, core::AddressType::DATA);
  address_map_->AddXref(0xC000, 0x8000);

  LabelGenerator generator(address_map_.get(), nullptr, &symbol_table);
  generator.GenerateLabels();

  // Should use symbol table name if available
  EXPECT_TRUE(address_map_->HasLabel(0xC000));
  // The label should match or be based on the symbol
  auto label_opt = address_map_->GetLabel(0xC000);
  ASSERT_TRUE(label_opt.has_value());
  EXPECT_FALSE(label_opt->empty());
}

// Test edge case: address at 0x0000
TEST_F(LabelGeneratorTest, ZeroAddress) {
  address_map_->SetType(0x0000, core::AddressType::DATA);

  LabelGenerator generator(address_map_.get());
  std::string label = generator.GenerateLabelForAddress(0x0000);

  EXPECT_FALSE(label.empty());
}

// Test edge case: address at 0xFFFF
TEST_F(LabelGeneratorTest, MaxAddress) {
  address_map_->SetType(0xFFFF, core::AddressType::CODE);

  LabelGenerator generator(address_map_.get());
  std::string label = generator.GenerateLabelForAddress(0xFFFF);

  EXPECT_FALSE(label.empty());
}

// Test that multiple entry points get unique labels
TEST_F(LabelGeneratorTest, MultipleEntryPoints) {
  address_map_->AddEntryPoint(0x8000);
  address_map_->AddEntryPoint(0x9000);
  address_map_->SetType(0x8000, core::AddressType::CODE);
  address_map_->SetType(0x9000, core::AddressType::CODE);

  LabelGenerator generator(address_map_.get());

  // Generate labels explicitly for each entry point
  std::string label1 = generator.GenerateLabelForAddress(0x8000);
  std::string label2 = generator.GenerateLabelForAddress(0x9000);

  EXPECT_FALSE(label1.empty());
  EXPECT_FALSE(label2.empty());
  EXPECT_NE(label1, label2);  // Labels should be unique
}

}  // namespace
}  // namespace analysis
}  // namespace sourcerer
