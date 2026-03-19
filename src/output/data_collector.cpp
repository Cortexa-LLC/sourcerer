// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "output/data_collector.h"

namespace sourcerer {
namespace output {

StringDetectionResult DataCollector::DetectString(
    uint32_t address,
    uint32_t end_address,
    size_t lookahead) const {

  StringDetectionResult result;
  result.looks_like_string = false;
  result.has_high_bit = false;
  result.has_control_char = false;
  result.is_high_bit_ascii = false;
  result.printable_count = 0;

  if (!binary_) {
    return result;
  }

  size_t available = end_address - address;
  if (available < 3) {
    return result;
  }

  size_t check_len = std::min(lookahead, available);

  // Classify all bytes in the lookahead window
  bool all_have_high_bit = true;
  for (size_t i = 0; i < check_len; ++i) {
    const uint8_t* byte_ptr = binary_->GetPointer(address + i);
    if (!byte_ptr) {
      return result;
    }

    uint8_t byte = *byte_ptr;

    if (byte < 0x80) {
      all_have_high_bit = false;
    } else {
      result.has_high_bit = true;
    }

    // Control characters (except CR/LF) — only possible for low bytes
    if (byte < 0x20 && byte != 0x0D && byte != 0x0A) {
      result.has_control_char = true;
    }

    // IsPrintable strips bit 7, so this works for both regular and high-bit bytes
    if (IsPrintable(byte)) {
      result.printable_count++;
    }
  }

  // Standard ASCII: no high-bit bytes, no control chars, enough printable chars
  if (!result.has_high_bit && !result.has_control_char && result.printable_count >= 3) {
    result.looks_like_string = true;
    return result;
  }

  // Apple II high-bit ASCII: ALL bytes have bit 7 set and are printable after stripping.
  // Example: $A0=$20(space), $C1=$41('A'), $AA=$2A('*')
  if (all_have_high_bit &&
      result.printable_count == static_cast<int>(check_len)) {
    result.is_high_bit_ascii = true;
    result.looks_like_string = true;
    return result;
  }

  return result;
}

DataCollectionResult DataCollector::CollectStringData(
    uint32_t start_address,
    uint32_t end_address,
    const core::AddressMap* address_map,
    size_t max_length) const {

  DataCollectionResult result;
  result.next_address = start_address;

  if (!binary_) {
    return result;
  }

  uint32_t addr = start_address;

  while (addr < end_address &&
         address_map &&
         address_map->GetType(addr) != core::AddressType::CODE) {

    // Stop if this address has a label (it needs its own output line)
    if (addr != start_address && address_map->HasLabel(addr)) {
      break;
    }

    const uint8_t* byte = binary_->GetPointer(addr);
    if (!byte) break;

    uint8_t b = *byte;

    // Stop at null terminator (don't include it in the string)
    if (b == 0x00) {
      addr++;  // Skip the null terminator
      break;
    }

    // Stop if not printable (except CR)
    if (!((b & 0x7F) >= 0x20 && (b & 0x7F) < 0x7F) && b != 0x8D) {
      break;
    }

    result.bytes.push_back(b);
    addr++;

    // Limit string length
    if (result.bytes.size() >= max_length) break;
  }

  result.next_address = addr;
  return result;
}

DataCollectionResult DataCollector::CollectBinaryData(
    uint32_t start_address,
    uint32_t end_address,
    const core::AddressMap* address_map,
    size_t max_bytes) const {

  DataCollectionResult result;
  result.next_address = start_address;

  if (!binary_) {
    return result;
  }

  uint32_t addr = start_address;

  while (addr < end_address &&
         (!address_map ||
          address_map->GetType(addr) != core::AddressType::CODE) &&
         result.bytes.size() < max_bytes) {

    // Stop if this address has a label (it needs its own output line)
    if (addr != start_address && address_map && address_map->HasLabel(addr)) {
      break;
    }

    const uint8_t* byte = binary_->GetPointer(addr);
    if (byte) {
      result.bytes.push_back(*byte);
    }
    addr++;
  }

  result.next_address = addr;
  return result;
}

}  // namespace output
}  // namespace sourcerer
