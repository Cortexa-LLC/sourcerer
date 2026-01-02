// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "utils/cli_parser.h"

#include <CLI/CLI.hpp>
#include <sstream>

namespace sourcerer {
namespace utils {

CliParser::CliParser() {}

bool CliParser::Parse(int argc, char** argv, CliOptions* options,
                      std::string* error) {
  CLI::App app{"Sourcerer - Modern Multi-CPU Disassembler"};

  // Input/output options
  app.add_option("-i,--input", options->input_file, "Input file (disk image or binary)");
  app.add_option("-o,--output", options->output_file, "Output assembly file");

  // CPU options
  app.add_option("-c,--cpu", options->cpu_type, "CPU type (6502, 65c02, etc.)")
      ->default_val("6502");

  // Disk options
  app.add_flag("-d,--disk", options->is_disk, "Input is a disk image");
  app.add_option("--file", options->disk_file_name,
                 "File to extract from disk");
  app.add_flag("--list-files", options->list_files,
               "List files in disk image and exit");

  // Address options
  auto addr_opt = app.add_option("-a,--address", options->load_address,
                                 "Load address for raw binary (hex)");
  addr_opt->transform(CLI::AsNumberWithUnit(
      std::map<std::string, uint32_t>{
          {"K", 1024}, {"M", 1024 * 1024}},
      CLI::AsNumberWithUnit::CASE_INSENSITIVE, "BYTE"));

  auto entry_opt = app.add_option("--entry", options->entry_point,
                                  "Entry point address (default: load address)");
  entry_opt->transform(CLI::AsNumberWithUnit(
      std::map<std::string, uint32_t>{
          {"K", 1024}, {"M", 1024 * 1024}},
      CLI::AsNumberWithUnit::CASE_INSENSITIVE, "BYTE"));

  // Analysis options
  app.add_option("-p,--platform", options->platform,
                 "Target platform (e.g., apple2) - auto-loads platform symbols");
  app.add_option("--hints", options->hints_file, "Hints file (JSON)");
  app.add_option("--symbols", options->symbols_files,
                 "Symbol table file(s) (JSON, can specify multiple)")
      ->expected(1, 999);  // Allow multiple symbol files
  app.add_flag("--no-analysis{false},!--no-analysis{true}",
               options->enable_analysis,
               "Disable code flow analysis (linear only)");
  app.add_flag("--xref", options->generate_xrefs, "Generate cross-references");

  // Output options
  app.add_option("-f,--format", options->output_format,
                 "Output format (merlin, scmasm, etc.)")
      ->default_val("merlin");
  app.add_flag("--no-labels{false},!--no-labels{true}", options->generate_labels,
               "Don't generate labels");
  app.add_flag("-v,--verbose", options->verbose, "Verbose output");

  // Parse
  try {
    app.parse(argc, argv);

    // Check if address options were set
    options->has_load_address = addr_opt->count() > 0;
    options->has_entry_point = entry_opt->count() > 0;

    // Store help text
    help_text_ = app.help();

    return true;
  } catch (const CLI::ParseError& e) {
    *error = "Command-line parse error: ";
    *error += e.what();
    help_text_ = app.help();
    return false;
  }
}

std::string CliParser::GetHelp() const {
  return help_text_;
}

}  // namespace utils
}  // namespace sourcerer
