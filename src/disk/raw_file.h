// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_DISK_RAW_FILE_H_
#define SOURCERER_DISK_RAW_FILE_H_

#include <memory>
#include <string>
#include <vector>

#include "disk/disk_extractor.h"

namespace sourcerer {
namespace disk {

// Raw binary file loader - handles any file that's not a disk image
class RawFileLoader : public DiskExtractor {
 public:
  RawFileLoader() = default;
  ~RawFileLoader() override = default;

  // DiskExtractor interface
  std::string Name() const override { return "RAW"; }
  bool CanHandle(const std::string& path) const override;
  std::vector<FileEntry> ListFiles(const std::string& disk_path) override;
  core::Binary ExtractFile(const std::string& disk_path,
                           const std::string& file_path) override;
  bool IsValidDisk(const std::string& disk_path) const override;

 private:
  // Get file size
  static size_t GetFileSize(const std::string& path);

  // Extract filename from path
  static std::string GetFilename(const std::string& path);
};

// Factory function
std::unique_ptr<DiskExtractor> CreateRawFileLoader();

}  // namespace disk
}  // namespace sourcerer

#endif  // SOURCERER_DISK_RAW_FILE_H_
