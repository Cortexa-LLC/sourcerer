// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "disk/raw_file.h"

#include <fstream>
#include <sys/stat.h>

#include "utils/logger.h"

namespace sourcerer {
namespace disk {

bool RawFileLoader::CanHandle(const std::string& path) const {
  // Raw file loader is a fallback - it can handle any file
  // But we should exclude known disk image formats
  if (path.size() >= 4) {
    std::string ext = path.substr(path.size() - 4);
    for (char& c : ext) c = tolower(c);
    
    // Exclude disk image formats that other extractors handle
    if (ext == ".dsk" || ext == ".do" || ext == ".po") {
      return false;
    }
  }
  
  // Check if file exists
  struct stat st;
  return stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

bool RawFileLoader::IsValidDisk(const std::string& disk_path) const {
  struct stat st;
  if (stat(disk_path.c_str(), &st) != 0) {
    return false;
  }
  return S_ISREG(st.st_mode);
}

std::vector<FileEntry> RawFileLoader::ListFiles(const std::string& disk_path) {
  std::vector<FileEntry> files;
  
  size_t size = GetFileSize(disk_path);
  if (size == 0) {
    LOG_WARNING("File is empty or could not be read: " + disk_path);
    return files;
  }
  
  FileEntry entry;
  entry.name = GetFilename(disk_path);
  entry.path = disk_path;
  entry.file_type = "BIN";
  entry.size = static_cast<uint32_t>(size);
  entry.load_address = 0x8000;  // Default load address
  entry.has_load_address = false;  // User must specify
  
  files.push_back(entry);
  return files;
}

core::Binary RawFileLoader::ExtractFile(const std::string& disk_path,
                                        const std::string& file_path) {
  (void)file_path;  // Unused - raw files use disk_path directly
  // For raw files, disk_path and file_path should be the same
  // (or file_path should be empty/ignored)
  std::string actual_path = disk_path;
  
  // Load address must be specified by caller via Binary::set_load_address()
  // We use a default of 0x8000 for now
  uint32_t load_address = 0x8000;
  
  LOG_INFO("Loading raw binary from: " + actual_path);
  
  core::Binary binary = core::Binary::LoadFromFile(actual_path, load_address);
  binary.set_file_type("RAW");
  binary.set_source_file(actual_path);
  
  return binary;
}

size_t RawFileLoader::GetFileSize(const std::string& path) {
  struct stat st;
  if (stat(path.c_str(), &st) != 0) {
    return 0;
  }
  return static_cast<size_t>(st.st_size);
}

std::string RawFileLoader::GetFilename(const std::string& path) {
  size_t pos = path.find_last_of("/\\");
  if (pos == std::string::npos) {
    return path;
  }
  return path.substr(pos + 1);
}

std::unique_ptr<DiskExtractor> CreateRawFileLoader() {
  return std::make_unique<RawFileLoader>();
}

}  // namespace disk
}  // namespace sourcerer
