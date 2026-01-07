// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_ANALYSIS_STRATEGIES_INLINE_DATA_SCANNER_H_
#define SOURCERER_ANALYSIS_STRATEGIES_INLINE_DATA_SCANNER_H_

#include <cstdint>
#include <map>
#include <set>

#include "core/address_map.h"
#include "core/binary.h"
#include "core/platform_hints.h"
#include "core/symbol_table.h"
#include "cpu/cpu_plugin.h"

namespace sourcerer {
namespace analysis {

// Strategy for detecting and scanning inline data after JSR calls
// Some routines (e.g., ProDOS MLI) expect data bytes immediately after JSR
// Extracted from CodeAnalyzer to follow Single Responsibility Principle
class InlineDataScanner {
 public:
  InlineDataScanner(cpu::CpuPlugin* cpu, const core::Binary* binary,
                    const core::PlatformHints* hints = nullptr);

  // Check if address is a known inline data routine
  bool IsInlineDataRoutine(uint32_t address, core::AddressMap* address_map);

  // Scan forward from start_address to find inline data and mark it
  // Returns address after data terminator, or 0 if no terminator found
  uint32_t ScanInlineData(uint32_t start_address,
                          core::AddressMap* address_map,
                          int* data_bytes_counter);

  // Register a known platform-specific inline data routine
  // address: routine address
  // bytes_after_call: number of inline data bytes after JSR
  void RegisterKnownRoutine(uint32_t address, size_t bytes_after_call);

  // Check if address is a registered known routine, return byte count if so
  bool IsKnownRoutine(uint32_t address, size_t* bytes_after_call) const;

  // Scan for JSR/LBSR calls to known inline data routines and mark data bytes
  // This should be called BEFORE main code flow analysis
  // Uses symbol table to add descriptive comments for MLI calls
  // Returns number of inline data bytes marked
  int ScanAndMarkInlineData(const std::vector<core::Instruction>& instructions,
                            core::AddressMap* address_map,
                            const core::SymbolTable* symbol_table = nullptr);

  // Helper to check if address is valid
  bool IsValidAddress(uint32_t address) const;

 private:
  cpu::CpuPlugin* cpu_;
  const core::Binary* binary_;
  const core::PlatformHints* hints_;

  // Detected inline data routines (PLA/TSX pattern)
  std::set<uint32_t> inline_data_routines_;

  // Known platform-specific routines (address -> bytes_after_call)
  std::map<uint32_t, size_t> known_inline_data_routines_;

  // Constants
  static constexpr size_t kMaxInlineDataSize = 256;
};

}  // namespace analysis
}  // namespace sourcerer

#endif  // SOURCERER_ANALYSIS_STRATEGIES_INLINE_DATA_SCANNER_H_
