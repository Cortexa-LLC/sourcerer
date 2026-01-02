// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "analysis/hints_parser.h"

#include <gtest/gtest.h>

#include <fstream>

namespace sourcerer {
namespace analysis {
namespace {

// Test fixture for HintsParser tests
class HintsParserTest : public ::testing::Test {
 protected:
  void SetUp() override {
    parser_ = std::make_unique<HintsParser>();
  }

  std::unique_ptr<HintsParser> parser_;
};

// Test parsing basic JSON with entry points
TEST_F(HintsParserTest, ParseEntryPoints) {
  std::string json = R"({
    "entry_points": ["0x8000", "0x9000"]
  })";

  Hints hints;
  std::string error;
  EXPECT_TRUE(parser_->ParseJson(json, &hints, &error)) << error;

  ASSERT_EQ(hints.entry_points.size(), 2);
  EXPECT_EQ(hints.entry_points[0], 0x8000);
  EXPECT_EQ(hints.entry_points[1], 0x9000);
}

// Test parsing decimal addresses
TEST_F(HintsParserTest, ParseDecimalAddresses) {
  std::string json = R"({
    "entry_points": ["32768", "36864"]
  })";

  Hints hints;
  std::string error;
  EXPECT_TRUE(parser_->ParseJson(json, &hints, &error)) << error;

  ASSERT_EQ(hints.entry_points.size(), 2);
  EXPECT_EQ(hints.entry_points[0], 32768);  // 0x8000
  EXPECT_EQ(hints.entry_points[1], 36864);  // 0x9000
}

// Test parsing hex addresses with $ prefix
TEST_F(HintsParserTest, ParseDollarHexAddresses) {
  std::string json = R"({
    "entry_points": ["$8000", "$9000"]
  })";

  Hints hints;
  std::string error;
  EXPECT_TRUE(parser_->ParseJson(json, &hints, &error)) << error;

  ASSERT_EQ(hints.entry_points.size(), 2);
  EXPECT_EQ(hints.entry_points[0], 0x8000);
  EXPECT_EQ(hints.entry_points[1], 0x9000);
}

// Test parsing code regions
TEST_F(HintsParserTest, ParseCodeRegions) {
  std::string json = R"({
    "code_regions": [
      {"start": "0x8000", "end": "0x8FFF"}
    ]
  })";

  Hints hints;
  std::string error;
  EXPECT_TRUE(parser_->ParseJson(json, &hints, &error)) << error;

  ASSERT_EQ(hints.code_regions.size(), 1);
  EXPECT_EQ(hints.code_regions[0].start_address, 0x8000);
  EXPECT_EQ(hints.code_regions[0].end_address, 0x8FFF);
  EXPECT_EQ(hints.code_regions[0].type, core::AddressType::HINT_CODE);
}

// Test parsing data regions
TEST_F(HintsParserTest, ParseDataRegions) {
  std::string json = R"({
    "data_regions": [
      {"start": "0x9000", "end": "0x9100"}
    ]
  })";

  Hints hints;
  std::string error;
  EXPECT_TRUE(parser_->ParseJson(json, &hints, &error)) << error;

  ASSERT_EQ(hints.data_regions.size(), 1);
  EXPECT_EQ(hints.data_regions[0].start_address, 0x9000);
  EXPECT_EQ(hints.data_regions[0].end_address, 0x9100);
  EXPECT_EQ(hints.data_regions[0].type, core::AddressType::HINT_DATA);
}

// Test parsing labels
TEST_F(HintsParserTest, ParseLabels) {
  std::string json = R"({
    "labels": {
      "0x8000": "MAIN",
      "0x8010": "INIT_SCREEN"
    }
  })";

  Hints hints;
  std::string error;
  EXPECT_TRUE(parser_->ParseJson(json, &hints, &error)) << error;

  ASSERT_EQ(hints.labels.size(), 2);
  EXPECT_EQ(hints.labels[0x8000], "MAIN");
  EXPECT_EQ(hints.labels[0x8010], "INIT_SCREEN");
}

// Test parsing comments
TEST_F(HintsParserTest, ParseComments) {
  std::string json = R"({
    "comments": {
      "0x8000": "Program entry point",
      "0x8010": "Initialize screen"
    }
  })";

  Hints hints;
  std::string error;
  EXPECT_TRUE(parser_->ParseJson(json, &hints, &error)) << error;

  ASSERT_EQ(hints.comments.size(), 2);
  EXPECT_EQ(hints.comments[0x8000], "Program entry point");
  EXPECT_EQ(hints.comments[0x8010], "Initialize screen");
}

// Test parsing complete hints file
TEST_F(HintsParserTest, ParseCompleteHints) {
  std::string json = R"({
    "entry_points": ["0x8000"],
    "code_regions": [
      {"start": "0x8000", "end": "0x8FFF"}
    ],
    "data_regions": [
      {"start": "0x9000", "end": "0x9100"}
    ],
    "labels": {
      "0x8000": "MAIN",
      "0x9000": "DATA_TABLE"
    },
    "comments": {
      "0x8000": "Program entry"
    }
  })";

  Hints hints;
  std::string error;
  EXPECT_TRUE(parser_->ParseJson(json, &hints, &error)) << error;

  EXPECT_EQ(hints.entry_points.size(), 1);
  EXPECT_EQ(hints.code_regions.size(), 1);
  EXPECT_EQ(hints.data_regions.size(), 1);
  EXPECT_EQ(hints.labels.size(), 2);
  EXPECT_EQ(hints.comments.size(), 1);
}

// Test parsing empty hints file
TEST_F(HintsParserTest, ParseEmptyHints) {
  std::string json = "{}";

  Hints hints;
  std::string error;
  EXPECT_TRUE(parser_->ParseJson(json, &hints, &error)) << error;

  EXPECT_TRUE(hints.entry_points.empty());
  EXPECT_TRUE(hints.code_regions.empty());
  EXPECT_TRUE(hints.data_regions.empty());
  EXPECT_TRUE(hints.labels.empty());
  EXPECT_TRUE(hints.comments.empty());
}

// Test parsing invalid JSON
TEST_F(HintsParserTest, ParseInvalidJson) {
  std::string json = "{ invalid json }";

  Hints hints;
  std::string error;
  EXPECT_FALSE(parser_->ParseJson(json, &hints, &error));
  EXPECT_FALSE(error.empty());
}

// Test parsing malformed address
TEST_F(HintsParserTest, ParseMalformedAddress) {
  std::string json = R"({
    "entry_points": ["not_an_address"]
  })";

  Hints hints;
  std::string error;
  EXPECT_FALSE(parser_->ParseJson(json, &hints, &error));
  EXPECT_FALSE(error.empty());
}

// Test parsing file
TEST_F(HintsParserTest, ParseFile) {
  // Create temporary hints file
  const std::string temp_file = "/tmp/test_hints.json";
  std::ofstream out(temp_file);
  out << R"({
    "entry_points": ["0x8000"],
    "labels": {
      "0x8000": "START"
    }
  })";
  out.close();

  Hints hints;
  std::string error;
  EXPECT_TRUE(parser_->ParseFile(temp_file, &hints, &error)) << error;

  EXPECT_EQ(hints.entry_points.size(), 1);
  EXPECT_EQ(hints.labels.size(), 1);
  EXPECT_EQ(hints.labels[0x8000], "START");

  // Clean up
  std::remove(temp_file.c_str());
}

// Test parsing non-existent file
TEST_F(HintsParserTest, ParseNonExistentFile) {
  Hints hints;
  std::string error;
  EXPECT_FALSE(parser_->ParseFile("/tmp/nonexistent_file.json", &hints, &error));
  EXPECT_FALSE(error.empty());
}

// Test ApplyHints to AddressMap
TEST_F(HintsParserTest, ApplyHints) {
  Hints hints;
  hints.entry_points.push_back(0x8000);

  RegionHint code_region;
  code_region.start_address = 0x8000;
  code_region.end_address = 0x8FFF;
  code_region.type = core::AddressType::HINT_CODE;
  hints.code_regions.push_back(code_region);

  RegionHint data_region;
  data_region.start_address = 0x9000;
  data_region.end_address = 0x9100;
  data_region.type = core::AddressType::HINT_DATA;
  hints.data_regions.push_back(data_region);

  hints.labels[0x8000] = "MAIN";
  hints.labels[0x9000] = "DATA_TABLE";
  hints.comments[0x8000] = "Entry point";

  core::AddressMap addr_map;
  HintsParser::ApplyHints(hints, &addr_map);

  // Verify entry points
  EXPECT_EQ(addr_map.GetEntryPoints().size(), 1);
  EXPECT_TRUE(addr_map.GetEntryPoints().count(0x8000) > 0);

  // Verify code region types (spot check a few addresses)
  EXPECT_EQ(addr_map.GetType(0x8000), core::AddressType::HINT_CODE);
  EXPECT_EQ(addr_map.GetType(0x8500), core::AddressType::HINT_CODE);
  EXPECT_EQ(addr_map.GetType(0x8FFF), core::AddressType::HINT_CODE);

  // Verify data region types
  EXPECT_EQ(addr_map.GetType(0x9000), core::AddressType::HINT_DATA);
  EXPECT_EQ(addr_map.GetType(0x9080), core::AddressType::HINT_DATA);
  EXPECT_EQ(addr_map.GetType(0x9100), core::AddressType::HINT_DATA);

  // Verify labels
  EXPECT_TRUE(addr_map.HasLabel(0x8000));
  EXPECT_EQ(addr_map.GetLabel(0x8000), "MAIN");
  EXPECT_TRUE(addr_map.HasLabel(0x9000));
  EXPECT_EQ(addr_map.GetLabel(0x9000), "DATA_TABLE");

  // Verify comments
  EXPECT_TRUE(addr_map.HasComment(0x8000));
  EXPECT_EQ(addr_map.GetComment(0x8000), "Entry point");
}

// Test multiple code regions
TEST_F(HintsParserTest, MultipleCodeRegions) {
  std::string json = R"({
    "code_regions": [
      {"start": "0x8000", "end": "0x8FFF"},
      {"start": "0xA000", "end": "0xAFFF"}
    ]
  })";

  Hints hints;
  std::string error;
  EXPECT_TRUE(parser_->ParseJson(json, &hints, &error)) << error;

  ASSERT_EQ(hints.code_regions.size(), 2);
  EXPECT_EQ(hints.code_regions[0].start_address, 0x8000);
  EXPECT_EQ(hints.code_regions[1].start_address, 0xA000);
}

// Test address formats in labels
TEST_F(HintsParserTest, MixedAddressFormats) {
  std::string json = R"({
    "labels": {
      "0x8000": "HEX_PREFIX",
      "$8010": "DOLLAR_PREFIX",
      "32800": "DECIMAL"
    }
  })";

  Hints hints;
  std::string error;
  EXPECT_TRUE(parser_->ParseJson(json, &hints, &error)) << error;

  ASSERT_EQ(hints.labels.size(), 3);
  EXPECT_EQ(hints.labels[0x8000], "HEX_PREFIX");
  EXPECT_EQ(hints.labels[0x8010], "DOLLAR_PREFIX");
  EXPECT_EQ(hints.labels[32800], "DECIMAL");
}

// Test edge case: zero address
TEST_F(HintsParserTest, ZeroAddress) {
  std::string json = R"({
    "entry_points": ["0x0000"],
    "labels": {
      "0": "ZP_START"
    }
  })";

  Hints hints;
  std::string error;
  EXPECT_TRUE(parser_->ParseJson(json, &hints, &error)) << error;

  EXPECT_EQ(hints.entry_points[0], 0);
  EXPECT_EQ(hints.labels[0], "ZP_START");
}

// Test edge case: high addresses
TEST_F(HintsParserTest, HighAddresses) {
  std::string json = R"({
    "entry_points": ["0xFFFF"],
    "labels": {
      "0xFFFF": "END"
    }
  })";

  Hints hints;
  std::string error;
  EXPECT_TRUE(parser_->ParseJson(json, &hints, &error)) << error;

  EXPECT_EQ(hints.entry_points[0], 0xFFFF);
  EXPECT_EQ(hints.labels[0xFFFF], "END");
}

// Test region with single address
TEST_F(HintsParserTest, SingleAddressRegion) {
  std::string json = R"({
    "code_regions": [
      {"start": "0x8000", "end": "0x8000"}
    ]
  })";

  Hints hints;
  std::string error;
  EXPECT_TRUE(parser_->ParseJson(json, &hints, &error)) << error;

  ASSERT_EQ(hints.code_regions.size(), 1);
  EXPECT_EQ(hints.code_regions[0].start_address, 0x8000);
  EXPECT_EQ(hints.code_regions[0].end_address, 0x8000);
}

// Test special characters in labels
TEST_F(HintsParserTest, SpecialCharsInLabels) {
  std::string json = R"({
    "labels": {
      "0x8000": "LABEL_WITH_UNDERSCORE",
      "0x8010": "LABEL123",
      "0x8020": ":LOCAL_LABEL"
    }
  })";

  Hints hints;
  std::string error;
  EXPECT_TRUE(parser_->ParseJson(json, &hints, &error)) << error;

  EXPECT_EQ(hints.labels[0x8000], "LABEL_WITH_UNDERSCORE");
  EXPECT_EQ(hints.labels[0x8010], "LABEL123");
  EXPECT_EQ(hints.labels[0x8020], ":LOCAL_LABEL");
}

// Test multiline comments
TEST_F(HintsParserTest, MultilineComments) {
  std::string json = R"({
    "comments": {
      "0x8000": "This is a long comment\nthat spans multiple lines"
    }
  })";

  Hints hints;
  std::string error;
  EXPECT_TRUE(parser_->ParseJson(json, &hints, &error)) << error;

  EXPECT_TRUE(hints.comments[0x8000].find("long comment") != std::string::npos);
  EXPECT_TRUE(hints.comments[0x8000].find("multiple lines") != std::string::npos);
}

}  // namespace
}  // namespace analysis
}  // namespace sourcerer
