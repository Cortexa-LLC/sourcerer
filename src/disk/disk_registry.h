// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_DISK_DISK_REGISTRY_H_
#define SOURCERER_DISK_DISK_REGISTRY_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "disk/disk_extractor.h"

namespace sourcerer {
namespace disk {

// Registry for disk extractors
class DiskRegistry {
 public:
  static DiskRegistry& Instance();

  // Register a disk extractor
  void Register(const std::string& name, DiskExtractorFactory factory);

  // Create a disk extractor by name
  std::unique_ptr<DiskExtractor> Create(const std::string& name) const;

  // Find appropriate extractor for a disk file
  std::unique_ptr<DiskExtractor> FindExtractor(const std::string& path) const;

  // Check if an extractor is registered
  bool IsRegistered(const std::string& name) const;

  // Get list of registered extractor names
  std::vector<std::string> GetRegisteredNames() const;

  // Prevent copying
  DiskRegistry(const DiskRegistry&) = delete;
  DiskRegistry& operator=(const DiskRegistry&) = delete;

 private:
  DiskRegistry();
  void RegisterBuiltinExtractors();

  std::vector<std::pair<std::string, DiskExtractorFactory>> factories_;
};

}  // namespace disk
}  // namespace sourcerer

#endif  // SOURCERER_DISK_DISK_REGISTRY_H_
