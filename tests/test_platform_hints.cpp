// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include <gtest/gtest.h>
#include "core/platform_hints.h"

namespace sourcerer {
namespace core {
namespace {

class PlatformHintsTest : public ::testing::Test {
 protected:
  void SetUp() override {
    hints_ = std::make_unique<PlatformHints>();
  }

  std::unique_ptr<PlatformHints> hints_;
};

// Test: Load valid hints JSON
TEST_F(PlatformHintsTest, LoadValidJson) {
  std::string json = R"({
    "platform": "Apple II + ProDOS",
    "description": "Test hints",
    "version": "1.0",
    "inline_data_routines": [
      {
        "address": "0xBF00",
        "name": "MLI",
        "description": "ProDOS Machine Language Interface",
        "pattern": "JSR_BYTE_WORD",
        "bytes_after_call": 3
      }
    ],
    "mli_parameter_structures": {
      "0xC8": {
        "name": "OPEN",
        "description": "Open a file"
      },
      "0x65": {
        "name": "QUIT",
        "description": "Quit to ProDOS dispatcher"
      }
    }
  })";

  ASSERT_TRUE(hints_->LoadFromJson(json));
  EXPECT_EQ(hints_->GetPlatform(), "Apple II + ProDOS");
}

// Test: Get inline data routine
TEST_F(PlatformHintsTest, GetInlineDataRoutine) {
  std::string json = R"({
    "platform": "test",
    "inline_data_routines": [
      {
        "address": "0xBF00",
        "name": "MLI",
        "bytes_after_call": 3
      }
    ]
  })";

  ASSERT_TRUE(hints_->LoadFromJson(json));

  size_t bytes = 0;
  EXPECT_TRUE(hints_->IsInlineDataRoutine(0xBF00, &bytes));
  EXPECT_EQ(bytes, 3);
  EXPECT_FALSE(hints_->IsInlineDataRoutine(0xBF01, &bytes));
}

// Test: Get MLI call name
TEST_F(PlatformHintsTest, GetMliCallName) {
  std::string json = R"({
    "platform": "test",
    "mli_parameter_structures": {
      "0xC8": {
        "name": "OPEN",
        "description": "Open a file"
      }
    }
  })";

  ASSERT_TRUE(hints_->LoadFromJson(json));

  auto call_info = hints_->GetMliCallInfo(0xC8);
  ASSERT_TRUE(call_info.has_value());
  EXPECT_EQ(call_info->name, "OPEN");
  EXPECT_EQ(call_info->description, "Open a file");

  EXPECT_FALSE(hints_->GetMliCallInfo(0xFF).has_value());
}

// Test: Load from file
TEST_F(PlatformHintsTest, LoadFromFile) {
  // Test loading from actual apple2_prodos_hints.json
  std::string path = "../symbols/apple2_prodos_hints.json";

  if (hints_->LoadFromFile(path)) {
    EXPECT_EQ(hints_->GetPlatform(), "Apple II + ProDOS");

    // Should have MLI routine
    size_t bytes = 0;
    EXPECT_TRUE(hints_->IsInlineDataRoutine(0xBF00, &bytes));
    EXPECT_EQ(bytes, 3);

    // Should have OPEN call
    auto call_info = hints_->GetMliCallInfo(0xC8);
    ASSERT_TRUE(call_info.has_value());
    EXPECT_EQ(call_info->name, "OPEN");
  } else {
    // File might not exist in test environment, that's ok
    GTEST_SKIP() << "apple2_prodos_hints.json not found";
  }
}

// Test: Invalid JSON
TEST_F(PlatformHintsTest, LoadInvalidJson) {
  std::string json = "{ invalid json }";
  EXPECT_FALSE(hints_->LoadFromJson(json));
}

// Test: Empty hints
TEST_F(PlatformHintsTest, EmptyHints) {
  std::string json = R"({
    "platform": "test"
  })";

  ASSERT_TRUE(hints_->LoadFromJson(json));

  size_t bytes = 0;
  EXPECT_FALSE(hints_->IsInlineDataRoutine(0xBF00, &bytes));
  EXPECT_FALSE(hints_->GetMliCallInfo(0xC8).has_value());
}

// Test: Multiple inline data routines
TEST_F(PlatformHintsTest, MultipleInlineDataRoutines) {
  std::string json = R"({
    "platform": "test",
    "inline_data_routines": [
      {
        "address": "0xBF00",
        "name": "MLI",
        "bytes_after_call": 3
      },
      {
        "address": "0xFE00",
        "name": "CUSTOM",
        "bytes_after_call": 2
      }
    ]
  })";

  ASSERT_TRUE(hints_->LoadFromJson(json));

  size_t bytes = 0;
  EXPECT_TRUE(hints_->IsInlineDataRoutine(0xBF00, &bytes));
  EXPECT_EQ(bytes, 3);

  EXPECT_TRUE(hints_->IsInlineDataRoutine(0xFE00, &bytes));
  EXPECT_EQ(bytes, 2);
}

// Test: MLI call with parameter structure
TEST_F(PlatformHintsTest, MliCallWithParameters) {
  std::string json = R"json({
    "platform": "test",
    "mli_parameter_structures": {
      "0xC8": {
        "name": "OPEN",
        "description": "Open a file",
        "parameters": [
          {"offset": 0, "size": 1, "name": "param_count", "description": "Parameter count (3)"},
          {"offset": 1, "size": 2, "name": "pathname", "description": "Pointer to pathname"},
          {"offset": 3, "size": 2, "name": "io_buffer", "description": "I/O buffer pointer"},
          {"offset": 5, "size": 1, "name": "ref_num", "description": "Reference number (returned)"}
        ]
      }
    }
  })json";

  ASSERT_TRUE(hints_->LoadFromJson(json));

  auto call_info = hints_->GetMliCallInfo(0xC8);
  ASSERT_TRUE(call_info.has_value());
  EXPECT_EQ(call_info->name, "OPEN");
  EXPECT_EQ(call_info->description, "Open a file");
  ASSERT_EQ(call_info->parameters.size(), 4);

  // Check first parameter
  EXPECT_EQ(call_info->parameters[0].offset, 0);
  EXPECT_EQ(call_info->parameters[0].size, 1);
  EXPECT_EQ(call_info->parameters[0].name, "param_count");
  EXPECT_EQ(call_info->parameters[0].description, "Parameter count (3)");

  // Check last parameter
  EXPECT_EQ(call_info->parameters[3].offset, 5);
  EXPECT_EQ(call_info->parameters[3].size, 1);
  EXPECT_EQ(call_info->parameters[3].name, "ref_num");
  EXPECT_EQ(call_info->parameters[3].description, "Reference number (returned)");
}

// Test: Load parameter structures from real file
TEST_F(PlatformHintsTest, LoadParametersFromFile) {
  std::string path = "../symbols/apple2_prodos_hints.json";

  if (hints_->LoadFromFile(path)) {
    // Check OPEN call parameters
    auto open_info = hints_->GetMliCallInfo(0xC8);
    ASSERT_TRUE(open_info.has_value());
    EXPECT_EQ(open_info->name, "OPEN");
    ASSERT_FALSE(open_info->parameters.empty());
    EXPECT_EQ(open_info->parameters[0].name, "param_count");

    // Check QUIT call parameters
    auto quit_info = hints_->GetMliCallInfo(0x65);
    ASSERT_TRUE(quit_info.has_value());
    EXPECT_EQ(quit_info->name, "QUIT");
    ASSERT_FALSE(quit_info->parameters.empty());

    // Check GET_FILE_INFO call parameters
    auto info_call = hints_->GetMliCallInfo(0xC4);
    ASSERT_TRUE(info_call.has_value());
    EXPECT_EQ(info_call->name, "GET_FILE_INFO");
    ASSERT_FALSE(info_call->parameters.empty());
  } else {
    GTEST_SKIP() << "apple2_prodos_hints.json not found";
  }
}

}  // namespace
}  // namespace core
}  // namespace sourcerer
