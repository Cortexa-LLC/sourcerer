// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_ANALYSIS_ANALYSIS_CONFIG_H_
#define SOURCERER_ANALYSIS_ANALYSIS_CONFIG_H_

#include <cstddef>
#include <cstdint>
#include <string>

#include "core/constants.h"

namespace sourcerer {
namespace analysis {

// Configuration for code analysis
struct AnalysisConfig {
  // Entry point configuration
  uint32_t entry_point = 0;
  bool has_entry_point = false;

  // Analysis limits
  size_t max_instructions = constants::kDefaultMaxInstructions;
  int max_passes = constants::kMaxAnalysisPasses;

  // Feature flags
  bool enable_jump_table_detection = true;
  bool enable_misalignment_resolution = true;
  bool enable_entry_point_discovery = true;
  bool enable_data_reclassification = true;

  // Hints file (optional)
  std::string hints_file;

  // Statistics output
  bool verbose_statistics = false;

  // Create default configuration
  static AnalysisConfig Default() {
    return AnalysisConfig{};
  }

  // Create configuration with specific entry point
  static AnalysisConfig WithEntryPoint(uint32_t address) {
    AnalysisConfig config;
    config.entry_point = address;
    config.has_entry_point = true;
    return config;
  }
};

}  // namespace analysis
}  // namespace sourcerer

#endif  // SOURCERER_ANALYSIS_ANALYSIS_CONFIG_H_
