// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_ANALYSIS_DISASSEMBLY_ORCHESTRATOR_H
#define SOURCERER_ANALYSIS_DISASSEMBLY_ORCHESTRATOR_H

#include <vector>

#include "core/address_map.h"
#include "core/binary.h"
#include "core/instruction.h"
#include "core/symbol_table.h"
#include "cpu/cpu_plugin.h"

namespace sourcerer {
namespace analysis {

// Orchestrates disassembly operations (with or without code flow analysis)
class DisassemblyOrchestrator {
 public:
  DisassemblyOrchestrator(cpu::CpuPlugin* cpu, const core::Binary* binary);

  // Disassemble with full code flow analysis
  std::vector<core::Instruction> DisassembleWithAnalysis(
      core::AddressMap* address_map,
      uint32_t entry_point = 0,
      const core::SymbolTable* symbol_table = nullptr);

  // Linear disassembly (no code flow analysis)
  std::vector<core::Instruction> DisassembleLinear();

 private:
  cpu::CpuPlugin* cpu_;
  const core::Binary* binary_;
};

}  // namespace analysis
}  // namespace sourcerer

#endif  // SOURCERER_ANALYSIS_DISASSEMBLY_ORCHESTRATOR_H
