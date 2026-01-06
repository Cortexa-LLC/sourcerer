// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "core/address_map.h"

namespace sourcerer {
namespace core {

AddressMap::AddressMap() {}

void AddressMap::SetType(uint32_t address, AddressType type) {
  address_types_[address] = type;
}

AddressType AddressMap::GetType(uint32_t address) const {
  auto it = address_types_.find(address);
  if (it != address_types_.end()) {
    return it->second;
  }
  return AddressType::UNKNOWN;
}

bool AddressMap::IsCode(uint32_t address) const {
  AddressType type = GetType(address);
  return type == AddressType::CODE || type == AddressType::HINT_CODE;
}

bool AddressMap::IsData(uint32_t address) const {
  AddressType type = GetType(address);
  return type == AddressType::DATA || type == AddressType::INLINE_DATA ||
         type == AddressType::HINT_DATA;
}

void AddressMap::SetLabel(uint32_t address, const std::string& label) {
  labels_[address] = label;
}

bool AddressMap::HasLabel(uint32_t address) const {
  return labels_.find(address) != labels_.end();
}

std::optional<std::string> AddressMap::GetLabel(uint32_t address) const {
  auto it = labels_.find(address);
  if (it != labels_.end()) {
    return it->second;
  }
  return std::nullopt;
}

void AddressMap::SetComment(uint32_t address, const std::string& comment) {
  comments_[address] = comment;
}

void AddressMap::AppendComment(uint32_t address, const std::string& comment) {
  auto it = comments_.find(address);
  if (it != comments_.end()) {
    it->second += comment;
  } else {
    comments_[address] = comment;
  }
}

bool AddressMap::HasComment(uint32_t address) const {
  return comments_.find(address) != comments_.end();
}

std::optional<std::string> AddressMap::GetComment(uint32_t address) const {
  auto it = comments_.find(address);
  if (it != comments_.end()) {
    return it->second;
  }
  return std::nullopt;
}

void AddressMap::AddXref(uint32_t target, uint32_t source) {
  xrefs_.insert(std::make_pair(target, source));
}

void AddressMap::RemoveXrefsFrom(uint32_t source) {
  // Remove all xrefs where this address is the source
  // xrefs_ is multimap<target, source>, so we need to scan all entries
  auto it = xrefs_.begin();
  while (it != xrefs_.end()) {
    if (it->second == source) {
      it = xrefs_.erase(it);  // erase returns next valid iterator
    } else {
      ++it;
    }
  }
}

std::vector<uint32_t> AddressMap::GetXrefs(uint32_t target) const {
  std::vector<uint32_t> result;
  auto range = xrefs_.equal_range(target);
  for (auto it = range.first; it != range.second; ++it) {
    result.push_back(it->second);
  }
  return result;
}

bool AddressMap::HasXrefs(uint32_t target) const {
  return xrefs_.find(target) != xrefs_.end();
}

void AddressMap::AddEntryPoint(uint32_t address) {
  entry_points_.insert(address);
}

void AddressMap::Clear() {
  address_types_.clear();
  labels_.clear();
  comments_.clear();
  xrefs_.clear();
  entry_points_.clear();
}

}  // namespace core
}  // namespace sourcerer
