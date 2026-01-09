// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_OUTPUT_MERLIN_FORMATTER_H_
#define SOURCERER_OUTPUT_MERLIN_FORMATTER_H_

#include <memory>
#include <string>
#include <vector>

#include "output/formatter.h"
#include "output/address_analyzer.h"

namespace sourcerer {
namespace output {

// Merlin assembler syntax formatter
// Based on vasm-ext/syntax/merlin documentation
class MerlinFormatter : public Formatter {
 public:
  MerlinFormatter() = default;
  ~MerlinFormatter() override = default;

  // Formatter interface
  std::string Name() const override { return "Merlin"; }

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
  // Column positions for Merlin format
  static constexpr int LABEL_COL = 0;
  static constexpr int OPCODE_COL = 9;
  static constexpr int OPERAND_COL = 14;
  static constexpr int COMMENT_COL = 40;  // Increased to accommodate longer symbols

  // Helper: Format address as hex string
  std::string FormatAddress(uint32_t address, int width = 4) const;

  // Helper: Format label for address
  std::string GetLabel(uint32_t address,
                      const core::AddressMap* address_map) const;

  // Helper: Format a data region (detects strings vs binary)
  std::string FormatDataRegion(uint32_t address,
                              const std::vector<uint8_t>& bytes,
                              const core::AddressMap* address_map,
                              const core::SymbolTable* symbol_table = nullptr,
                              const core::Binary* binary = nullptr,
                              const AddressAnalyzer* address_analyzer = nullptr);

  // Helper: Check if label represents a subroutine (needs separator)
  bool IsSubroutineLabel(const std::string& label) const;

  // Helper: Generate contextual comment for branch instructions
  std::string GenerateBranchComment(const std::string& mnemonic) const;
};

// Factory function
std::unique_ptr<Formatter> CreateMerlinFormatter();

}  // namespace output
}  // namespace sourcerer

#endif  // SOURCERER_OUTPUT_MERLIN_FORMATTER_H_
