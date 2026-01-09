// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_CORE_ADDRESS_MAP_H_
#define SOURCERER_CORE_ADDRESS_MAP_H_

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace sourcerer {
namespace core {

// Type of data at an address
enum class AddressType {
  UNKNOWN,      // Not yet analyzed
  CODE,         // Executable code
  DATA,         // Data bytes
  INLINE_DATA,  // Data embedded after JSR (strings, tables read by subroutine)
  HINT_CODE,    // User hinted as code
  HINT_DATA,    // User hinted as data
};

// Tracks information about addresses in the binary
class AddressMap {
 public:
  AddressMap();

  // Type tracking
  void SetType(uint32_t address, AddressType type);
  AddressType GetType(uint32_t address) const noexcept;
  bool IsCode(uint32_t address) const noexcept;
  bool IsData(uint32_t address) const noexcept;

  // Label management (C++ Core Guidelines F.20: prefer return values)
  void SetLabel(uint32_t address, const std::string& label);
  [[nodiscard]] std::optional<std::string> GetLabel(uint32_t address) const;

  // Legacy API for backwards compatibility (deprecated)
  bool HasLabel(uint32_t address) const noexcept;

  const std::map<uint32_t, std::string>& GetAllLabels() const noexcept { return labels_; }

  // Comment management (C++ Core Guidelines F.20: prefer return values)
  void SetComment(uint32_t address, const std::string& comment);
  void AppendComment(uint32_t address, const std::string& comment);
  [[nodiscard]] std::optional<std::string> GetComment(uint32_t address) const;

  // Legacy API for backwards compatibility (deprecated)
  bool HasComment(uint32_t address) const noexcept;

  // Cross-reference tracking
  void AddXref(uint32_t target, uint32_t source);
  void RemoveXrefsFrom(uint32_t source);  // Remove all xrefs originating from source
  std::vector<uint32_t> GetXrefs(uint32_t target) const;
  bool HasXrefs(uint32_t target) const noexcept;
  const std::multimap<uint32_t, uint32_t>& GetAllXrefs() const noexcept { return xrefs_; }

  // Entry points
  void AddEntryPoint(uint32_t address);
  const std::set<uint32_t>& GetEntryPoints() const noexcept { return entry_points_; }

  // Clear all data
  void Clear();

 private:
  std::map<uint32_t, AddressType> address_types_;
  std::map<uint32_t, std::string> labels_;
  std::map<uint32_t, std::string> comments_;
  std::multimap<uint32_t, uint32_t> xrefs_;  // target -> source(s)
  std::set<uint32_t> entry_points_;
};

}  // namespace core
}  // namespace sourcerer

#endif  // SOURCERER_CORE_ADDRESS_MAP_H_
