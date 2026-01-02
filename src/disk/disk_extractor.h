// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_DISK_DISK_EXTRACTOR_H_
#define SOURCERER_DISK_DISK_EXTRACTOR_H_

#include <memory>
#include <string>
#include <vector>

#include "core/binary.h"

namespace sourcerer {
namespace disk {

// File entry information from disk image
struct FileEntry {
  std::string name;
  std::string path;          // Full path (e.g., "SOURCEROR/OBJ")
  std::string file_type;     // "BIN", "SYS", "TXT", etc.
  uint32_t size;
  uint32_t load_address;     // For BIN/SYS files
  bool has_load_address;
  std::string modification_date;
};

// Abstract disk extractor interface
class DiskExtractor {
 public:
  virtual ~DiskExtractor() = default;

  // Extractor identification
  virtual std::string Name() const = 0;

  // Check if this extractor can handle the file
  virtual bool CanHandle(const std::string& path) const = 0;

  // List files in disk image
  virtual std::vector<FileEntry> ListFiles(const std::string& disk_path) = 0;

  // Extract file from disk image
  virtual core::Binary ExtractFile(const std::string& disk_path,
                                   const std::string& file_path) = 0;

  // Check if disk image exists and is valid
  virtual bool IsValidDisk(const std::string& disk_path) const = 0;
};

// Factory function type for creating disk extractors
using DiskExtractorFactory = std::unique_ptr<DiskExtractor> (*)();

}  // namespace disk
}  // namespace sourcerer

#endif  // SOURCERER_DISK_DISK_EXTRACTOR_H_
