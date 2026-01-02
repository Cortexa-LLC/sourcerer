// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "core/binary.h"

#include <gtest/gtest.h>

#include <fstream>
#include <vector>

namespace sourcerer {
namespace core {
namespace {

// Test fixture for Binary class
class BinaryTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Create sample test data
    test_data_ = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
  }

  std::vector<uint8_t> test_data_;
};

// Test default constructor
TEST_F(BinaryTest, DefaultConstructor) {
  Binary binary;
  EXPECT_EQ(binary.size(), 0);
  EXPECT_EQ(binary.load_address(), 0);
  EXPECT_TRUE(binary.source_file().empty());
  EXPECT_TRUE(binary.file_type().empty());
}

// Test constructor with data and load address
TEST_F(BinaryTest, ConstructorWithData) {
  Binary binary(test_data_, 0x8000);
  EXPECT_EQ(binary.size(), test_data_.size());
  EXPECT_EQ(binary.load_address(), 0x8000);
  EXPECT_EQ(binary.data(), test_data_);
}

// Test IsValidAddress
TEST_F(BinaryTest, IsValidAddress) {
  Binary binary(test_data_, 0x8000);

  // Valid addresses
  EXPECT_TRUE(binary.IsValidAddress(0x8000));  // First byte
  EXPECT_TRUE(binary.IsValidAddress(0x8005));  // Middle byte
  EXPECT_TRUE(binary.IsValidAddress(0x800F));  // Last byte

  // Invalid addresses
  EXPECT_FALSE(binary.IsValidAddress(0x7FFF));  // Before start
  EXPECT_FALSE(binary.IsValidAddress(0x8010));  // After end
}

// Test GetByte
TEST_F(BinaryTest, GetByte) {
  Binary binary(test_data_, 0x8000);

  EXPECT_EQ(binary.GetByte(0x8000), 0x00);
  EXPECT_EQ(binary.GetByte(0x8005), 0x05);
  EXPECT_EQ(binary.GetByte(0x800F), 0x0F);
}

// Test GetBytes
TEST_F(BinaryTest, GetBytes) {
  Binary binary(test_data_, 0x8000);

  // Get first 4 bytes
  std::vector<uint8_t> bytes = binary.GetBytes(0x8000, 4);
  EXPECT_EQ(bytes.size(), 4);
  EXPECT_EQ(bytes[0], 0x00);
  EXPECT_EQ(bytes[1], 0x01);
  EXPECT_EQ(bytes[2], 0x02);
  EXPECT_EQ(bytes[3], 0x03);

  // Get bytes from middle
  bytes = binary.GetBytes(0x8008, 3);
  EXPECT_EQ(bytes.size(), 3);
  EXPECT_EQ(bytes[0], 0x08);
  EXPECT_EQ(bytes[1], 0x09);
  EXPECT_EQ(bytes[2], 0x0A);
}

// Test GetPointer
TEST_F(BinaryTest, GetPointer) {
  Binary binary(test_data_, 0x8000);

  const uint8_t* ptr = binary.GetPointer(0x8000);
  ASSERT_NE(ptr, nullptr);
  EXPECT_EQ(*ptr, 0x00);
  EXPECT_EQ(*(ptr + 5), 0x05);

  // Pointer at end
  ptr = binary.GetPointer(0x800F);
  ASSERT_NE(ptr, nullptr);
  EXPECT_EQ(*ptr, 0x0F);

  // Invalid address should return nullptr
  ptr = binary.GetPointer(0x8010);
  EXPECT_EQ(ptr, nullptr);
}

// Test mutators
TEST_F(BinaryTest, Mutators) {
  Binary binary(test_data_, 0x8000);

  binary.set_load_address(0x9000);
  EXPECT_EQ(binary.load_address(), 0x9000);

  binary.set_source_file("test.bin");
  EXPECT_EQ(binary.source_file(), "test.bin");

  binary.set_file_type("RAW");
  EXPECT_EQ(binary.file_type(), "RAW");
}

// Test with different load addresses
TEST_F(BinaryTest, DifferentLoadAddresses) {
  // Zero page
  Binary zp_binary(test_data_, 0x00);
  EXPECT_TRUE(zp_binary.IsValidAddress(0x00));
  EXPECT_TRUE(zp_binary.IsValidAddress(0x0F));
  EXPECT_FALSE(zp_binary.IsValidAddress(0x10));

  // High memory
  Binary high_binary(test_data_, 0xFFF0);
  EXPECT_TRUE(high_binary.IsValidAddress(0xFFF0));
  EXPECT_TRUE(high_binary.IsValidAddress(0xFFFF));
  EXPECT_FALSE(high_binary.IsValidAddress(0x10000));
}

// Test edge cases
TEST_F(BinaryTest, EdgeCases) {
  // Empty binary
  Binary empty_binary({}, 0x8000);
  EXPECT_EQ(empty_binary.size(), 0);
  EXPECT_FALSE(empty_binary.IsValidAddress(0x8000));

  // Single byte binary
  Binary single_binary({0x42}, 0x8000);
  EXPECT_EQ(single_binary.size(), 1);
  EXPECT_TRUE(single_binary.IsValidAddress(0x8000));
  EXPECT_FALSE(single_binary.IsValidAddress(0x8001));
  EXPECT_EQ(single_binary.GetByte(0x8000), 0x42);
}

// Test large binary (64KB)
TEST_F(BinaryTest, LargeBinary) {
  std::vector<uint8_t> large_data(65536);
  for (size_t i = 0; i < large_data.size(); ++i) {
    large_data[i] = static_cast<uint8_t>(i & 0xFF);
  }

  Binary binary(large_data, 0x0000);
  EXPECT_EQ(binary.size(), 65536);
  EXPECT_TRUE(binary.IsValidAddress(0x0000));
  EXPECT_TRUE(binary.IsValidAddress(0xFFFF));
  EXPECT_FALSE(binary.IsValidAddress(0x10000));

  // Verify data pattern
  EXPECT_EQ(binary.GetByte(0x0100), 0x00);
  EXPECT_EQ(binary.GetByte(0x0155), 0x55);
  EXPECT_EQ(binary.GetByte(0xFFFF), 0xFF);
}

// Test LoadFromFile with a temporary file
TEST_F(BinaryTest, LoadFromFile) {
  // Create a temporary test file
  const std::string temp_file = "/tmp/test_binary.bin";
  std::ofstream out(temp_file, std::ios::binary);
  out.write(reinterpret_cast<const char*>(test_data_.data()), test_data_.size());
  out.close();

  // Load the file
  Binary binary = Binary::LoadFromFile(temp_file, 0x8000);
  EXPECT_EQ(binary.size(), test_data_.size());
  EXPECT_EQ(binary.load_address(), 0x8000);
  EXPECT_EQ(binary.source_file(), temp_file);
  EXPECT_EQ(binary.data(), test_data_);

  // Clean up
  std::remove(temp_file.c_str());
}

// Test GetBytes with boundary conditions
TEST_F(BinaryTest, GetBytesBoundary) {
  Binary binary(test_data_, 0x8000);

  // Request more bytes than available
  std::vector<uint8_t> bytes = binary.GetBytes(0x800C, 10);
  EXPECT_EQ(bytes.size(), 4);  // Only 4 bytes available from 0x800C to end

  // Request from invalid address
  bytes = binary.GetBytes(0x8010, 5);
  EXPECT_TRUE(bytes.empty());
}

}  // namespace
}  // namespace core
}  // namespace sourcerer
