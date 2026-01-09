// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_OUTPUT_SCMASM_FORMATTER_H_
#define SOURCERER_OUTPUT_SCMASM_FORMATTER_H_

#include <memory>
#include <string>
#include <vector>

#include "output/formatter.h"

namespace sourcerer {
namespace output {

// SCMASM 3.1 assembler syntax formatter
// Based on vasm-ext/syntax/scmasm documentation
class ScmasmFormatter : public Formatter {
 public:
  ScmasmFormatter() = default;
  ~ScmasmFormatter() override = default;

  // Formatter interface
  std::string Name() const override { return "SCMASM"; }

  std::string Format(const core::Binary& binary,
                    const std::vector<core::Instruction>& instructions,
                    const core::AddressMap* address_map = nullptr,
                    const core::SymbolTable* symbol_table = nullptr,
                    const core::IEquateProvider* equate_gen = nullptr) override;

  std::string FormatInstruction(
      const core::Instruction& inst,
      const core::AddressMap* address_map = nullptr,
      const core::SymbolTable* symbol_table = nullptr,
      const core::IEquateProvider* equate_gen = nullptr) override;

  std::string FormatData(uint32_t address,
                        const std::vector<uint8_t>& bytes) override;

  std::string FormatHeader(const core::Binary& binary) override;

  std::string FormatFooter() override;

 private:
  // Helper: Format a data region (detects strings vs binary)
  std::string FormatDataRegion(uint32_t address,
                              const std::vector<uint8_t>& bytes,
                              const core::AddressMap* address_map,
                              const core::SymbolTable* symbol_table = nullptr,
                              const core::Binary* binary = nullptr);

  // Column positions for SCMASM format
  static constexpr int LABEL_COL = 0;
  static constexpr int OPCODE_COL = 9;
  static constexpr int OPERAND_COL = 14;
  static constexpr int COMMENT_COL = 40;

  // Line numbering for SCMASM format
  static constexpr int LINE_NUMBER_START = 1000;
  static constexpr int LINE_NUMBER_INCREMENT = 10;

  // Helper: Format address as hex string
  std::string FormatAddress(uint32_t address, int width = 4) const;

  // Helper: Format line number (e.g., "1000 ")
  std::string FormatLineNumber(int line_num) const;

  // Helper: Add line numbers to all lines in the output
  std::string AddLineNumbers(const std::string& text) const;

  // Helper: Format label for address
  std::string GetLabel(uint32_t address,
                      const core::AddressMap* address_map) const;

  // Helper: Check if label represents a subroutine (needs separator)
  bool IsSubroutineLabel(const std::string& label) const;

  // Helper: Generate contextual comment for branch instructions
  std::string GenerateBranchComment(const std::string& mnemonic) const;
};

// Factory function
std::unique_ptr<Formatter> CreateScmasmFormatter();

}  // namespace output
}  // namespace sourcerer

#endif  // SOURCERER_OUTPUT_SCMASM_FORMATTER_H_
