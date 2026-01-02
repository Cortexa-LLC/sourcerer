// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_ANALYSIS_XREF_BUILDER_H_
#define SOURCERER_ANALYSIS_XREF_BUILDER_H_

#include <string>
#include <vector>

#include "core/address_map.h"
#include "core/instruction.h"

namespace sourcerer {
namespace analysis {

// Builds cross-references showing where addresses are referenced from
class XrefBuilder {
 public:
  explicit XrefBuilder(core::AddressMap* address_map);

  // Build cross-references from a list of instructions
  // This analyzes each instruction and records what addresses it references
  void BuildXrefs(const std::vector<core::Instruction>& instructions);

  // Generate cross-reference comment for an address
  // Returns formatted string like "Referenced from: $8000, $8050"
  // Returns empty string if address has no xrefs
  std::string GenerateXrefComment(uint32_t address) const;

  // Add cross-reference comments to address map
  // This updates the address map with xref comments for all referenced addresses
  void AddXrefComments();

 private:
  core::AddressMap* address_map_;

  // Maximum number of xrefs to show in a comment (to avoid huge comments)
  static constexpr int MAX_XREFS_IN_COMMENT = 10;

  // Helper: Format address as hex string
  std::string FormatAddress(uint32_t address) const;

  // Helper: Format address with label if available
  std::string FormatAddressWithLabel(uint32_t address) const;
};

}  // namespace analysis
}  // namespace sourcerer

#endif  // SOURCERER_ANALYSIS_XREF_BUILDER_H_
