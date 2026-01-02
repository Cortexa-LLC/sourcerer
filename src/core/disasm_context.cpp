// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "core/disasm_context.h"

namespace sourcerer {
namespace core {

DisasmContext::DisasmContext()
    : cpu_type_("6502"),
      output_format_("merlin"),
      entry_point_(0),
      enable_analysis_(true),
      generate_labels_(true),
      generate_xrefs_(false),
      verbose_(false) {}

DisasmContext::DisasmContext(const Binary& binary)
    : binary_(binary),
      cpu_type_("6502"),
      output_format_("merlin"),
      entry_point_(binary.load_address()),
      enable_analysis_(true),
      generate_labels_(true),
      generate_xrefs_(false),
      verbose_(false) {}

}  // namespace core
}  // namespace sourcerer
