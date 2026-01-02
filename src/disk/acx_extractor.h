// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_DISK_ACX_EXTRACTOR_H_
#define SOURCERER_DISK_ACX_EXTRACTOR_H_

#include <memory>
#include <string>
#include <vector>

#include "disk/disk_extractor.h"

namespace sourcerer {
namespace disk {

// Disk extractor using ACX.jar (AppleCommander eXperimental)
// Handles DOS 3.3 and ProDOS disk images
class AcxExtractor : public DiskExtractor {
 public:
  AcxExtractor();
  explicit AcxExtractor(const std::string& acx_path);
  ~AcxExtractor() override = default;

  // DiskExtractor interface
  std::string Name() const override { return "ACX"; }
  bool CanHandle(const std::string& path) const override;
  std::vector<FileEntry> ListFiles(const std::string& disk_path) override;
  core::Binary ExtractFile(const std::string& disk_path,
                           const std::string& file_path) override;
  bool IsValidDisk(const std::string& disk_path) const override;

 private:
  std::string acx_jar_path_;
  std::string temp_dir_;

  // Execute ACX.jar command and capture output
  std::string ExecuteAcx(const std::string& args) const;

  // Parse ACX list output to extract file entries
  std::vector<FileEntry> ParseListOutput(const std::string& output);

  // Parse load address from ProDOS/DOS 3.3 metadata
  uint32_t ParseLoadAddress(const std::string& metadata);

  // Find ACX.jar in common locations
  static std::string FindAcxJar();
};

// Factory function
std::unique_ptr<DiskExtractor> CreateAcxExtractor();

}  // namespace disk
}  // namespace sourcerer

#endif  // SOURCERER_DISK_ACX_EXTRACTOR_H_
