// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_UTILS_CLI_PARSER_H_
#define SOURCERER_UTILS_CLI_PARSER_H_

#include <cstdint>
#include <string>
#include <vector>

namespace sourcerer {
namespace utils {

// Command-line options parsed from arguments
struct CliOptions {
  // Required
  std::string input_file;
  std::string output_file;

  // CPU options
  std::string cpu_type = "6502";

  // Disk options
  bool is_disk = false;
  std::string disk_file_name;
  bool list_files = false;

  // Address options
  uint32_t load_address = 0;
  uint32_t entry_point = 0;
  bool has_load_address = false;
  bool has_entry_point = false;

  // Analysis options
  std::string platform;                    // Target platform (e.g., "apple2")
  std::string hints_file;
  std::vector<std::string> symbols_files;  // Symbol table JSON files
  bool enable_analysis = true;
  bool generate_xrefs = false;

  // Output options
  std::string output_format = "merlin";
  bool generate_labels = true;
  bool verbose = false;
};

// CLI parser
class CliParser {
 public:
  CliParser();

  // Parse command-line arguments
  bool Parse(int argc, char** argv, CliOptions* options, std::string* error);

  // Get help text
  std::string GetHelp() const;

 private:
  std::string help_text_;
};

}  // namespace utils
}  // namespace sourcerer

#endif  // SOURCERER_UTILS_CLI_PARSER_H_
