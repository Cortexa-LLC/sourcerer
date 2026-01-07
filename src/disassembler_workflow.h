// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_DISASSEMBLER_WORKFLOW_H
#define SOURCERER_DISASSEMBLER_WORKFLOW_H

#include <string>

#include "core/binary.h"
#include "utils/cli_parser.h"

namespace sourcerer {

// Orchestrates the complete disassembly workflow from CLI to output
class DisassemblerWorkflow {
 public:
  DisassemblerWorkflow() = default;

  // Main entry point - runs the complete workflow
  int Run(int argc, char** argv);

 private:
  // Load binary from raw file or disk image
  core::Binary LoadBinary(const utils::CliOptions& options);

  // List files in a disk image
  int ListDiskFiles(const std::string& disk_path);
};

}  // namespace sourcerer

#endif  // SOURCERER_DISASSEMBLER_WORKFLOW_H
