// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "disk/acx_extractor.h"

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <sys/stat.h>

#include "utils/logger.h"

namespace sourcerer {
namespace disk {

AcxExtractor::AcxExtractor() : temp_dir_("/tmp/sourcerer") {
  acx_jar_path_ = FindAcxJar();
  if (acx_jar_path_.empty()) {
    LOG_ERROR("ACX.jar not found in standard locations");
  } else {
    LOG_DEBUG("Found ACX.jar at: " + acx_jar_path_);
  }
}

AcxExtractor::AcxExtractor(const std::string& acx_path)
    : acx_jar_path_(acx_path), temp_dir_("/tmp/sourcerer") {}

std::string AcxExtractor::FindAcxJar() {
  const char* locations[] = {
      "/usr/local/share/java/acx.jar",
      "/usr/local/share/java/ac.jar",
      "/usr/share/java/acx.jar",
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

bool AcxExtractor::CanHandle(const std::string& path) const {
  if (path.size() >= 4) {
    std::string ext = path.substr(path.size() - 4);
    for (char& c : ext) c = tolower(c);
    if (ext == ".dsk" || ext == ".do" || ext == ".po") return true;
  }
  return false;
}

bool AcxExtractor::IsValidDisk(const std::string& disk_path) const {
  struct stat st;
  if (stat(disk_path.c_str(), &st) != 0) return false;
  
  try {
    std::string cmd = "java -jar \"" + acx_jar_path_ + "\" list --disk=\"" +
                     disk_path + "\" 2>&1";
    std::string output = ExecuteAcx(cmd);
    return output.find("Error") == std::string::npos;
  } catch (...) {
    return false;
  }
}

std::vector<FileEntry> AcxExtractor::ListFiles(const std::string& disk_path) {
  std::vector<FileEntry> files;
  if (acx_jar_path_.empty()) {
    LOG_ERROR("ACX.jar not available");
    return files;
  }

  std::string cmd = "java -jar \"" + acx_jar_path_ + "\" list --disk=\"" +
                   disk_path + "\" -r 2>&1";
  std::string output = ExecuteAcx(cmd);
  
  if (output.empty()) {
    LOG_ERROR("Failed to list files from disk: " + disk_path);
    return files;
  }
  
  return ParseListOutput(output);
}

core::Binary AcxExtractor::ExtractFile(const std::string& disk_path,
                                       const std::string& file_path) {
  if (acx_jar_path_.empty()) {
    throw std::runtime_error("ACX.jar not available");
  }

  system(("mkdir -p \"" + temp_dir_ + "\"").c_str());

  std::string cmd = "java -jar \"" + acx_jar_path_ + "\" export --disk=\"" +
                   disk_path + "\" --raw --output=\"" + temp_dir_ + "/\" \"" +
                   file_path + "\" 2>&1";

  LOG_DEBUG("Executing: " + cmd);
  std::string output = ExecuteAcx(cmd);

  std::string extracted_path = temp_dir_ + "/" + file_path;
  std::string dump_path = extracted_path + ".dump";

  struct stat st;
  if (stat(dump_path.c_str(), &st) == 0) {
    extracted_path = dump_path;
  }

  uint32_t load_address = 0x8000;
  core::Binary binary = core::Binary::LoadFromFile(extracted_path, load_address);
  binary.set_file_type("PRODOS");
  binary.set_source_file(disk_path + ":" + file_path);

  return binary;
}

std::string AcxExtractor::ExecuteAcx(const std::string& cmd) const {
  FILE* pipe = popen(cmd.c_str(), "r");
  if (!pipe) {
    LOG_ERROR("Failed to execute ACX command");
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

std::vector<FileEntry> AcxExtractor::ParseListOutput(const std::string& output) {
  std::vector<FileEntry> files;
  std::istringstream iss(output);
  std::string line;

  while (std::getline(iss, line)) {
    if (line.empty() || line[0] == '-' || 
        line.find("File:") != std::string::npos ||
        line.find("Name:") != std::string::npos) {
      continue;
    }

    FileEntry entry;
    size_t pos = 0;
    if (line[0] == '*' || line[0] == ' ') pos = 2;

    size_t name_end = line.find_first_of(" \t", pos);
    if (name_end != std::string::npos) {
      entry.name = line.substr(pos, name_end - pos);
      entry.path = entry.name;
      entry.file_type = "BIN";
      entry.size = 0;
      entry.load_address = 0x8000;
      entry.has_load_address = true;

      if (!entry.name.empty()) {
        files.push_back(entry);
      }
    }
  }

  return files;
}

uint32_t AcxExtractor::ParseLoadAddress(const std::string& metadata) {
  size_t pos = metadata.find("A=$");
  if (pos != std::string::npos) {
    std::string addr_str = metadata.substr(pos + 3, 4);
    return std::stoul(addr_str, nullptr, 16);
  }
  return 0x8000;
}

std::unique_ptr<DiskExtractor> CreateAcxExtractor() {
  return std::make_unique<AcxExtractor>();
}

}  // namespace disk
}  // namespace sourcerer
