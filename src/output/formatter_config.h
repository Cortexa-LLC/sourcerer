// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_OUTPUT_FORMATTER_CONFIG_H_
#define SOURCERER_OUTPUT_FORMATTER_CONFIG_H_

#include "core/constants.h"

namespace sourcerer {
namespace output {

// Configuration for output formatting
struct FormatterConfig {
  // Label generation
  bool generate_labels = true;
  bool generate_equates = true;
  int min_equate_uses = constants::kMinEquateUses;

  // Cross-reference generation
  bool generate_xrefs = false;

  // Column positions
  int opcode_column = constants::kDefaultOpcodeColumn;
  int comment_column = constants::kDefaultCommentColumn;

  // Data formatting
  int max_bytes_per_line = constants::kMaxBytesPerLine;
  int max_data_bytes_per_line = constants::kMaxDataBytesPerLine;

  // Output style
  bool include_hex_dump = false;
  bool include_statistics = false;

  // Create default configuration
  static FormatterConfig Default() {
    return FormatterConfig{};
  }

  // Create configuration with cross-references enabled
  static FormatterConfig WithXrefs() {
    FormatterConfig config;
    config.generate_xrefs = true;
    return config;
  }

  // Create configuration with custom column positions
  static FormatterConfig WithColumns(int opcode_col, int comment_col) {
    FormatterConfig config;
    config.opcode_column = opcode_col;
    config.comment_column = comment_col;
    return config;
  }
};

}  // namespace output
}  // namespace sourcerer

#endif  // SOURCERER_OUTPUT_FORMATTER_CONFIG_H_
