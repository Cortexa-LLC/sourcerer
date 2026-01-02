// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "analysis/xref_builder.h"

#include <iomanip>
#include <sstream>
#include <algorithm>

namespace sourcerer {
namespace analysis {

XrefBuilder::XrefBuilder(core::AddressMap* address_map)
    : address_map_(address_map) {}

void XrefBuilder::BuildXrefs(const std::vector<core::Instruction>& instructions) {
  if (!address_map_) {
    return;
  }

  // Iterate through all instructions and record their target addresses
  for (const auto& inst : instructions) {
    // Check if this instruction has a target address
    if (inst.target_address != 0) {
      // Add cross-reference: target is referenced from this instruction's address
      address_map_->AddXref(inst.target_address, inst.address);
    }
  }
}

std::string XrefBuilder::GenerateXrefComment(uint32_t address) const {
  if (!address_map_ || !address_map_->HasXrefs(address)) {
    return "";
  }

  std::vector<uint32_t> xrefs = address_map_->GetXrefs(address);

  if (xrefs.empty()) {
    return "";
  }

  // Sort and deduplicate xrefs for consistent output
  std::sort(xrefs.begin(), xrefs.end());
  auto last = std::unique(xrefs.begin(), xrefs.end());
  xrefs.erase(last, xrefs.end());

  std::ostringstream out;
  out << "Referenced from: ";

  int count = 0;
  for (size_t i = 0; i < xrefs.size() && count < MAX_XREFS_IN_COMMENT; ++i) {
    if (i > 0) {
      out << ", ";
    }
    out << FormatAddressWithLabel(xrefs[i]);
    count++;
  }

  // If there are more xrefs than we displayed, add ellipsis
  if (xrefs.size() > static_cast<size_t>(MAX_XREFS_IN_COMMENT)) {
    out << "... (" << (xrefs.size() - MAX_XREFS_IN_COMMENT) << " more)";
  }

  return out.str();
}

void XrefBuilder::AddXrefComments() {
  if (!address_map_) {
    return;
  }

  // Get all addresses that have cross-references
  const auto& all_xrefs = address_map_->GetAllXrefs();

  // For each target address, generate and append xref comment
  std::set<uint32_t> targets;
  for (const auto& xref : all_xrefs) {
    targets.insert(xref.first);  // Collect unique target addresses
  }

  for (uint32_t target : targets) {
    std::string xref_comment = GenerateXrefComment(target);
    if (!xref_comment.empty()) {
      // Append to existing comment if there is one
      address_map_->AppendComment(target, xref_comment);
    }
  }
}

std::string XrefBuilder::FormatAddress(uint32_t address) const {
  std::ostringstream out;
  out << std::hex << std::uppercase << std::setw(4)
      << std::setfill('0') << address;
  return out.str();
}

std::string XrefBuilder::FormatAddressWithLabel(uint32_t address) const {
  if (!address_map_) {
    return "$" + FormatAddress(address);
  }

  // Check if this address has a label
  if (address_map_->HasLabel(address)) {
    std::string label = address_map_->GetLabel(address);
    return label;
  }

  // No label, just return address
  return "$" + FormatAddress(address);
}

}  // namespace analysis
}  // namespace sourcerer
