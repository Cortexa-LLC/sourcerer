// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "disk/disk_registry.h"

#include "disk/acx_extractor.h"
#include "disk/coco_extractor.h"
#include "disk/raw_file.h"
#include "utils/logger.h"

namespace sourcerer {
namespace disk {

DiskRegistry& DiskRegistry::Instance() {
  static DiskRegistry instance;
  return instance;
}

DiskRegistry::DiskRegistry() {
  RegisterBuiltinExtractors();
}

void DiskRegistry::RegisterBuiltinExtractors() {
  // Register CoCo extractor first (it has specific size detection)
  Register("coco", &CreateCocoExtractor);

  // Register ACX.jar extractor for Apple disk images
  Register("acx", &CreateAcxExtractor);

  // Register raw file loader
  Register("raw", &CreateRawFileLoader);

  LOG_INFO("Registered disk extractors");
}

void DiskRegistry::Register(const std::string& name,
                            DiskExtractorFactory factory) {
  factories_.push_back({name, factory});
  LOG_DEBUG("Registered disk extractor: " + name);
}

std::unique_ptr<DiskExtractor> DiskRegistry::Create(
    const std::string& name) const {
  for (const auto& pair : factories_) {
    if (pair.first == name) {
      return pair.second();
    }
  }
  LOG_ERROR("Disk extractor not found: " + name);
  return nullptr;
}

std::unique_ptr<DiskExtractor> DiskRegistry::FindExtractor(
    const std::string& path) const {
  // Try each registered extractor
  for (const auto& pair : factories_) {
    auto extractor = pair.second();
    if (extractor->CanHandle(path)) {
      LOG_DEBUG("Found extractor for " + path + ": " + pair.first);
      return extractor;
    }
  }

  LOG_WARNING("No extractor found for: " + path);
  return nullptr;
}

bool DiskRegistry::IsRegistered(const std::string& name) const {
  for (const auto& pair : factories_) {
    if (pair.first == name) {
      return true;
    }
  }
  return false;
}

std::vector<std::string> DiskRegistry::GetRegisteredNames() const {
  std::vector<std::string> names;
  for (const auto& pair : factories_) {
    names.push_back(pair.first);
  }
  return names;
}

}  // namespace disk
}  // namespace sourcerer
