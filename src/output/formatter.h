// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_OUTPUT_FORMATTER_H_
#define SOURCERER_OUTPUT_FORMATTER_H_

#include <memory>
#include <string>
#include <vector>

#include "core/address_map.h"
#include "core/binary.h"
#include "core/disasm_context.h"
#include "core/equate_provider.h"
#include "core/instruction.h"
#include "core/symbol_table.h"

namespace sourcerer {

namespace output {

// Abstract output formatter interface
class Formatter {
 public:
  virtual ~Formatter() = default;

  // Formatter identification
  virtual std::string Name() const = 0;

  // Format entire disassembly to string
  virtual std::string Format(const core::Binary& binary,
                            const std::vector<core::Instruction>& instructions,
                            const core::AddressMap* address_map = nullptr,
                            const core::SymbolTable* symbol_table = nullptr,
                            const core::IEquateProvider* equate_provider = nullptr) = 0;

  // Format individual instruction
  virtual std::string FormatInstruction(
      const core::Instruction& inst,
      const core::AddressMap* address_map = nullptr,
      const core::SymbolTable* symbol_table = nullptr,
      const core::IEquateProvider* equate_provider = nullptr) = 0;

  // Format data bytes
  virtual std::string FormatData(uint32_t address,
                                const std::vector<uint8_t>& bytes) = 0;

  // Format header/prologue
  virtual std::string FormatHeader(const core::Binary& binary) = 0;

  // Format footer/epilogue
  virtual std::string FormatFooter() = 0;
};

// Factory function type for creating formatters
using FormatterFactory = std::unique_ptr<Formatter> (*)();

}  // namespace output
}  // namespace sourcerer

#endif  // SOURCERER_OUTPUT_FORMATTER_H_
