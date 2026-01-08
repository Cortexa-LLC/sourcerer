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

// Test LoadFromFile with CoCo LOADM format
TEST_F(BinaryTest, LoadFromFileCoCoLOADM) {
  // Create a CoCo LOADM format file
  // Loop: while (offset + 5 <= data.size())
  // Preamble: 5 bytes, then data of length L
  // After processing segment: offset += L
  // So for offset + 5 to still be <= size after adding 5-byte preamble,
  // we need: (5 + L + 5) <= size, which means L <= size - 10
  const std::string temp_file = "/tmp/test_coco.bin";
  std::ofstream out(temp_file, std::ios::binary);

  std::vector<uint8_t> coco_data;

  // Preamble 1: 0x00 (flag), 0x00, 0x02 (length=2), 0x80, 0x00 (address=$8000)
  coco_data.push_back(0x00);  // Flag
  coco_data.push_back(0x00);  // Length high
  coco_data.push_back(0x02);  // Length low (2 bytes)
  coco_data.push_back(0x80);  // Address high
  coco_data.push_back(0x00);  // Address low

  // Segment data (2 bytes)
  coco_data.push_back(0x10);
  coco_data.push_back(0x20);

  // At this point: offset = 5 + 2 = 7, data.size() = 7
  // Loop checks: 7 + 5 <= 7? No, so loop exits
  // But the algorithm should still mark it as COCO_LOADM since segment_num >= 1

  // Postamble: 0xFF (flag), 0x80, 0x10 (execution address=$8010)
  // (This won't be reached by the loop but data is still valid LOADM format)
  coco_data.push_back(0xFF);  // Postamble flag
  coco_data.push_back(0x80);  // Execution address high
  coco_data.push_back(0x10);  // Execution address low

  out.write(reinterpret_cast<const char*>(coco_data.data()), coco_data.size());
  out.close();

  // Load the file
  Binary binary = Binary::LoadFromFile(temp_file, 0x0000);

  // Should be parsed as CoCo LOADM format
  EXPECT_EQ(binary.file_type(), "COCO_LOADM");
  EXPECT_TRUE(binary.is_multi_segment());
  // The segment should be present
  EXPECT_EQ(binary.segments().size(), 1);
  EXPECT_EQ(binary.segments()[0].load_address, 0x8000);
  EXPECT_EQ(binary.segments()[0].size(), 2);  // 2 bytes as specified in preamble
  EXPECT_EQ(binary.load_address(), 0x8000);
  EXPECT_EQ(binary.source_file(), temp_file);

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

// Test multi-segment binary creation
TEST_F(BinaryTest, MultiSegmentBinary) {
  Binary binary;
  binary.set_source_file("test_multi.bin");
  binary.set_file_type("COCO_LOADM");

  // Add first segment
  BinarySegment seg1;
  seg1.load_address = 0x8000;
  seg1.data = {0x00, 0x01, 0x02, 0x03, 0x04};
  binary.add_segment(seg1);

  // Add second segment
  BinarySegment seg2;
  seg2.load_address = 0xA000;
  seg2.data = {0x10, 0x11, 0x12, 0x13};
  binary.add_segment(seg2);

  EXPECT_TRUE(binary.is_multi_segment());
  EXPECT_EQ(binary.segments().size(), 2);
  EXPECT_EQ(binary.entry_point(), 0);  // Default entry point
}

// Test multi-segment IsValidAddress
TEST_F(BinaryTest, MultiSegmentIsValidAddress) {
  Binary binary;

  BinarySegment seg1;
  seg1.load_address = 0x8000;
  seg1.data = {0x00, 0x01, 0x02, 0x03};
  binary.add_segment(seg1);

  BinarySegment seg2;
  seg2.load_address = 0xA000;
  seg2.data = {0x10, 0x11};
  binary.add_segment(seg2);

  // Valid addresses in first segment
  EXPECT_TRUE(binary.IsValidAddress(0x8000));
  EXPECT_TRUE(binary.IsValidAddress(0x8003));

  // Valid addresses in second segment
  EXPECT_TRUE(binary.IsValidAddress(0xA000));
  EXPECT_TRUE(binary.IsValidAddress(0xA001));

  // Invalid addresses
  EXPECT_FALSE(binary.IsValidAddress(0x7FFF));
  EXPECT_FALSE(binary.IsValidAddress(0x8004));
  EXPECT_FALSE(binary.IsValidAddress(0x9FFF));
  EXPECT_FALSE(binary.IsValidAddress(0xA002));
}

// Test multi-segment GetByte
TEST_F(BinaryTest, MultiSegmentGetByte) {
  Binary binary;

  BinarySegment seg1;
  seg1.load_address = 0x8000;
  seg1.data = {0x00, 0x01, 0x02, 0x03};
  binary.add_segment(seg1);

  BinarySegment seg2;
  seg2.load_address = 0xA000;
  seg2.data = {0x10, 0x11};
  binary.add_segment(seg2);

  // Read from first segment
  EXPECT_EQ(binary.GetByte(0x8000), 0x00);
  EXPECT_EQ(binary.GetByte(0x8003), 0x03);

  // Read from second segment
  EXPECT_EQ(binary.GetByte(0xA000), 0x10);
  EXPECT_EQ(binary.GetByte(0xA001), 0x11);
}

// Test multi-segment GetBytes
TEST_F(BinaryTest, MultiSegmentGetBytes) {
  Binary binary;

  BinarySegment seg1;
  seg1.load_address = 0x8000;
  seg1.data = {0x00, 0x01, 0x02, 0x03, 0x04};
  binary.add_segment(seg1);

  BinarySegment seg2;
  seg2.load_address = 0xA000;
  seg2.data = {0x10, 0x11, 0x12};
  binary.add_segment(seg2);

  // Read from first segment
  std::vector<uint8_t> bytes = binary.GetBytes(0x8000, 3);
  EXPECT_EQ(bytes.size(), 3);
  EXPECT_EQ(bytes[0], 0x00);
  EXPECT_EQ(bytes[1], 0x01);
  EXPECT_EQ(bytes[2], 0x02);

  // Read from second segment
  bytes = binary.GetBytes(0xA000, 2);
  EXPECT_EQ(bytes.size(), 2);
  EXPECT_EQ(bytes[0], 0x10);
  EXPECT_EQ(bytes[1], 0x11);

  // Request beyond segment boundary
  bytes = binary.GetBytes(0xA001, 5);
  EXPECT_EQ(bytes.size(), 2);
}

// Test multi-segment GetPointer
TEST_F(BinaryTest, MultiSegmentGetPointer) {
  Binary binary;

  BinarySegment seg1;
  seg1.load_address = 0x8000;
  seg1.data = {0x00, 0x01, 0x02, 0x03};
  binary.add_segment(seg1);

  BinarySegment seg2;
  seg2.load_address = 0xA000;
  seg2.data = {0x10, 0x11};
  binary.add_segment(seg2);

  // Pointer in first segment
  const uint8_t* ptr = binary.GetPointer(0x8000);
  ASSERT_NE(ptr, nullptr);
  EXPECT_EQ(*ptr, 0x00);
  EXPECT_EQ(*(ptr + 2), 0x02);

  // Pointer in second segment
  ptr = binary.GetPointer(0xA000);
  ASSERT_NE(ptr, nullptr);
  EXPECT_EQ(*ptr, 0x10);

  // Invalid address
  ptr = binary.GetPointer(0x9000);
  EXPECT_EQ(ptr, nullptr);
}

// Test entry point for multi-segment binary
TEST_F(BinaryTest, MultiSegmentEntryPoint) {
  Binary binary;
  binary.set_entry_point(0x8100);

  BinarySegment seg;
  seg.load_address = 0x8000;
  seg.data = {0x00, 0x01, 0x02};
  binary.add_segment(seg);

  EXPECT_EQ(binary.entry_point(), 0x8100);
}

// Test empty multi-segment binary
TEST_F(BinaryTest, MultiSegmentEmpty) {
  Binary binary;
  EXPECT_FALSE(binary.is_multi_segment());
  EXPECT_TRUE(binary.segments().empty());
}

}  // namespace
}  // namespace core
}  // namespace sourcerer
