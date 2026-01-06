// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_OUTPUT_ADDRESS_ANALYZER_H_
#define SOURCERER_OUTPUT_ADDRESS_ANALYZER_H_

#include <cstdint>
#include <set>
#include <vector>

#include "core/address_map.h"
#include "core/binary.h"
#include "core/instruction.h"

namespace sourcerer {
namespace output {

// Address table detection result
struct AddressTableInfo {
  size_t length;   // Number of valid address bytes (always even)
  size_t offset;   // 0 or 1 (if table starts at byte 1)
  bool is_valid;   // True if at least 4 bytes form valid addresses
};

// Component responsible for analyzing addresses in binary
// Handles referenced address collection, address table detection, and validation
class AddressAnalyzer {
 public:
  AddressAnalyzer(const core::Binary* binary, const core::AddressMap* address_map)
      : binary_(binary), address_map_(address_map) {}

  // Collect all referenced addresses from instructions and data regions
  // Returns set of addresses that should have EQU/label definitions
  std::set<uint32_t> CollectReferencedAddresses(
      const std::vector<core::Instruction>& instructions) const;

  // Check if 16-bit value looks like a valid address
  bool LooksLikeAddress(uint16_t addr) const;

  // Find length and offset of address table in data
  // Handles both offset 0 and offset 1 tables
  AddressTableInfo FindAddressTableLengthAndOffset(
      const std::vector<uint8_t>& bytes) const;

 private:
  const core::Binary* binary_;
  const core::AddressMap* address_map_;
};

}  // namespace output
}  // namespace sourcerer

#endif  // SOURCERER_OUTPUT_ADDRESS_ANALYZER_H_
