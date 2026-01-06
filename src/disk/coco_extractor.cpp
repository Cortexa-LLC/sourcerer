// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "disk/coco_extractor.h"

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <sys/stat.h>

#include "utils/logger.h"

namespace sourcerer {
namespace disk {

CocoExtractor::CocoExtractor() : temp_dir_("/tmp/sourcerer") {
  cocofs_path_ = FindCocofs();
  if (cocofs_path_.empty()) {
    LOG_WARNING("cocofs not found in standard locations");
  } else {
    LOG_DEBUG("Found cocofs at: " + cocofs_path_);
  }
}

CocoExtractor::CocoExtractor(const std::string& cocofs_path)
    : cocofs_path_(cocofs_path), temp_dir_("/tmp/sourcerer") {
}

std::string CocoExtractor::FindCocofs() {
  const char* locations[] = {
      "/usr/local/bin/cocofs",
      "/usr/bin/cocofs",
      "/opt/homebrew/bin/cocofs",
      nullptr
  };

  struct stat st;
  for (int i = 0; locations[i] != nullptr; ++i) {
    if (stat(locations[i], &st) == 0) {
      return locations[i];
    }
  }
  return "";
}

bool CocoExtractor::CanHandle(const std::string& path) const {
  if (path.size() < 4) return false;

  std::string ext = path.substr(path.size() - 4);
  for (char& c : ext) c = std::tolower(static_cast<unsigned char>(c));

  LOG_INFO("CocoExtractor::CanHandle checking " + path + " (ext: " + ext + ")");

  // VDK is CoCo-specific
  if (ext == ".vdk") {
    LOG_INFO("Matched VDK extension");
    return true;
  }

  // For .dsk, detect if it's CoCo format by size
  if (ext == ".dsk") {
    std::string disk_type = DetectDiskType(path);
    LOG_INFO("Disk type detected: " + disk_type);
    return (disk_type == "COCO_DECB");
  }

  LOG_INFO("No match for CoCo disk");
  return false;
}

std::string CocoExtractor::DetectDiskType(const std::string& disk_path) const {
  struct stat st;
  if (stat(disk_path.c_str(), &st) != 0) return "UNKNOWN";

  // Common CoCo disk sizes:
  // - 161,280 bytes (35 track, SS, DD)
  // - 322,560 bytes (35 track, DS, DD)
  // - 368,640 bytes (40 track, DS, DD)
  // - 184,320 bytes (35 track, SS, QD)
  if (st.st_size == 161280 || st.st_size == 322560 ||
      st.st_size == 368640 || st.st_size == 184320) {
    return "COCO_DECB";
  }

  // Apple II sizes: 143,360 bytes (DOS 3.3), 140,800 bytes (ProDOS)
  if (st.st_size == 143360 || st.st_size == 140800) {
    return "APPLE2";
  }

  return "UNKNOWN";
}

bool CocoExtractor::IsValidDisk(const std::string& disk_path) const {
  if (cocofs_path_.empty()) return false;

  struct stat st;
  if (stat(disk_path.c_str(), &st) != 0) return false;

  // Try to list files - if it works, it's valid
  try {
    std::string cmd = "\"" + cocofs_path_ + "\" \"" + disk_path + "\" ls 2>&1";
    std::string output = ExecuteCocofs(cmd);
    return output.find("Error") == std::string::npos &&
           output.find("error") == std::string::npos;
  } catch (...) {
    return false;
  }
}

std::vector<FileEntry> CocoExtractor::ListFiles(const std::string& disk_path) {
  std::vector<FileEntry> files;

  if (cocofs_path_.empty()) {
    LOG_ERROR("cocofs not available");
    return files;
  }

  std::string cmd = "\"" + cocofs_path_ + "\" \"" + disk_path + "\" ls 2>&1";
  std::string output = ExecuteCocofs(cmd);

  if (output.empty()) {
    LOG_ERROR("Failed to list files from disk: " + disk_path);
    return files;
  }

  return ParseListOutput(output);
}

core::Binary CocoExtractor::ExtractFile(const std::string& disk_path,
                                        const std::string& file_path) {
  if (cocofs_path_.empty()) {
    throw std::runtime_error("cocofs not available");
  }

  // Create temp directory
  system(("mkdir -p \"" + temp_dir_ + "\"").c_str());

  // Extract file using cocofs copyout
  std::string output_file = temp_dir_ + "/" + file_path;
  std::string cmd = "cd \"" + temp_dir_ + "\" && \"" + cocofs_path_ +
                   "\" \"" + disk_path + "\" copyout \"" + file_path + "\" 2>&1";

  LOG_DEBUG("Executing: " + cmd);
  std::string output = ExecuteCocofs(cmd);

  // Check if file was extracted
  struct stat st;
  if (stat(output_file.c_str(), &st) != 0) {
    throw std::runtime_error("Failed to extract file: " + file_path + "\nOutput: " + output);
  }

  // Read the extracted file
  std::ifstream file(output_file, std::ios::binary);
  if (!file) {
    throw std::runtime_error("Failed to open extracted file: " + output_file);
  }

  std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
  file.close();

  // Parse CoCo ML binary header to get load address
  uint32_t load_address = ParseCocoLoadAddress(data.data(), data.size());

  // If we found a valid header, strip it
  size_t data_offset = 0;
  if (load_address != 0x2000) {  // Default wasn't used, header was found
    // Skip preamble and header
    if (data.size() >= 5 && data[0] == 0x00) {
      data_offset = 5;  // Skip: $00, load_addr_hi, load_addr_lo, length, next_byte
    }
  }

  // Create binary with data (stripping header if present)
  std::vector<uint8_t> binary_data(data.begin() + data_offset, data.end());
  core::Binary binary(binary_data, load_address);
  binary.set_source_file(disk_path + ":" + file_path);
  binary.set_file_type("DECB");

  // Clean up
  remove(output_file.c_str());

  LOG_INFO("Extracted " + file_path + " (" + std::to_string(binary.size()) +
           " bytes) from " + disk_path);
  LOG_INFO("Load address: $" + std::to_string(load_address));

  return binary;
}

std::string CocoExtractor::ExecuteCocofs(const std::string& cmd) const {
  FILE* pipe = popen(cmd.c_str(), "r");
  if (!pipe) {
    LOG_ERROR("Failed to execute cocofs command");
    return "";
  }

  std::ostringstream oss;
  char buffer[256];
  while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
    oss << buffer;
  }

  pclose(pipe);
  return oss.str();
}

std::vector<FileEntry> CocoExtractor::ParseListOutput(const std::string& output) {
  std::vector<FileEntry> files;
  std::istringstream iss(output);
  std::string line;

  // cocofs output format:
  // FILENAME   TYPE   SIZE bytes (Description)
  while (std::getline(iss, line)) {
    if (line.empty()) continue;

    // Skip summary lines
    if (line.find("file") != std::string::npos &&
        line.find("granules") != std::string::npos) {
      continue;
    }

    FileEntry entry;
    std::istringstream line_stream(line);

    // Extract filename (first token)
    line_stream >> entry.name;

    if (entry.name.empty() || entry.name == "cocofs") {
      continue;
    }

    // Extract file type
    line_stream >> entry.file_type;

    // Extract size
    line_stream >> entry.size;

    // Set defaults
    entry.path = entry.name;
    entry.load_address = 0x2000;  // Default CoCo ML load address
    entry.has_load_address = false;

    // File type determines if it's likely a binary
    if (entry.file_type == "BIN" || entry.file_type == "ML" ||
        entry.file_type == "OBJ") {
      entry.has_load_address = true;
    }

    files.push_back(entry);
  }

  return files;
}

uint32_t CocoExtractor::ParseCocoLoadAddress(const uint8_t* data, size_t size) {
  // CoCo ML binary format (optional header):
  // Byte 0: $00 (preamble)
  // Bytes 1-2: Load address (big-endian)
  // Byte 3: Block length
  // Bytes 4+: Data

  if (size < 5) {
    return 0x2000;  // Default load address
  }

  // Check for preamble
  if (data[0] == 0x00) {
    // Extract load address (big-endian)
    uint16_t load_addr = (static_cast<uint16_t>(data[1]) << 8) | data[2];

    // Sanity check: load address should be reasonable
    if (load_addr >= 0x0600 && load_addr <= 0x7F00) {
      LOG_DEBUG("Found CoCo ML header with load address: $" +
                std::to_string(load_addr));
      return load_addr;
    }
  }

  // No valid header found, use default
  return 0x2000;
}

std::unique_ptr<DiskExtractor> CreateCocoExtractor() {
  return std::make_unique<CocoExtractor>();
}

}  // namespace disk
}  // namespace sourcerer
