// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_DISK_COCO_EXTRACTOR_H_
#define SOURCERER_DISK_COCO_EXTRACTOR_H_

#include <memory>
#include <string>
#include <vector>

#include "disk/disk_extractor.h"

namespace sourcerer {
namespace disk {

// Disk extractor using cocofs
// Handles CoCo/Dragon DECB disk images (.dsk, .vdk)
class CocoExtractor : public DiskExtractor {
 public:
  CocoExtractor();
  explicit CocoExtractor(const std::string& cocofs_path);
  ~CocoExtractor() override = default;

  // DiskExtractor interface
  std::string Name() const override { return "CoCo"; }
  bool CanHandle(const std::string& path) const override;
  std::vector<FileEntry> ListFiles(const std::string& disk_path) override;
  core::Binary ExtractFile(const std::string& disk_path,
                           const std::string& file_path) override;
  bool IsValidDisk(const std::string& disk_path) const override;

 private:
  std::string cocofs_path_;
  std::string temp_dir_;

  // Execute cocofs command and capture output
  std::string ExecuteCocofs(const std::string& args) const;

  // Parse cocofs ls output to extract file entries
  std::vector<FileEntry> ParseListOutput(const std::string& output);

  // Parse CoCo ML binary header to extract load address
  uint32_t ParseCocoLoadAddress(const uint8_t* data, size_t size);

  // Detect CoCo disk type based on size
  std::string DetectDiskType(const std::string& disk_path) const;

  // Find cocofs in common locations
  static std::string FindCocofs();
};

// Factory function
std::unique_ptr<DiskExtractor> CreateCocoExtractor();

}  // namespace disk
}  // namespace sourcerer

#endif  // SOURCERER_DISK_COCO_EXTRACTOR_H_
