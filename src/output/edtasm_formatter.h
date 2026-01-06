// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_OUTPUT_EDTASM_FORMATTER_H_
#define SOURCERER_OUTPUT_EDTASM_FORMATTER_H_

#include <memory>
#include <string>
#include <vector>

#include "output/formatter.h"

namespace sourcerer {
namespace output {

// EDTASM+ assembler syntax formatter for 6809
// Based on Radio Shack Color Computer Disk EDTASM+ assembler
class EdtasmFormatter : public Formatter {
 public:
  EdtasmFormatter() = default;
  ~EdtasmFormatter() override = default;

  // Formatter interface
  std::string Name() const override { return "EDTASM+"; }

  std::string Format(const core::Binary& binary,
                    const std::vector<core::Instruction>& instructions,
                    const core::AddressMap* address_map = nullptr,
                    const core::SymbolTable* symbol_table = nullptr,
                    const analysis::EquateGenerator* equate_gen = nullptr) override;

  std::string FormatInstruction(
      const core::Instruction& inst,
      const core::AddressMap* address_map = nullptr,
      const core::SymbolTable* symbol_table = nullptr,
      const analysis::EquateGenerator* equate_gen = nullptr) override;

  std::string FormatData(uint32_t address,
                        const std::vector<uint8_t>& bytes) override;

  std::string FormatHeader(const core::Binary& binary) override;

  std::string FormatFooter() override;

 private:
  // Column positions for EDTASM+ format
  static constexpr int LABEL_COL = 0;
  static constexpr int OPCODE_COL = 9;
  static constexpr int OPERAND_COL = 15;
  static constexpr int COMMENT_COL = 40;

  // Helper: Format address as hex string
  std::string FormatAddress(uint32_t address, int width = 4) const;

  // Helper: Format label for address
  std::string GetLabel(uint32_t address,
                      const core::AddressMap* address_map) const;

  // Helper: Check if label represents a subroutine (needs separator)
  bool IsSubroutineLabel(const std::string& label) const;

  // Helper: Generate contextual comment for branch instructions
  std::string GenerateBranchComment(const std::string& mnemonic) const;

  // Helper: Generate semantic comment for instruction
  std::string GenerateSemanticComment(
      const core::Instruction& inst,
      const core::SymbolTable* symbol_table) const;

  // Helper: Check if operand references platform-specific hardware
  std::string GetPlatformHint(const std::string& operand,
                              const core::SymbolTable* symbol_table) const;

  // Helper: Detect register type from symbol name
  bool IsPlatformRegister(const std::string& symbol) const;

  // NEW: Data output helpers
  bool IsStringData(const uint8_t* data, size_t size) const;
  std::string FormatStringData(uint32_t address, const uint8_t* data, size_t size,
                               const core::AddressMap* address_map) const;
  std::string FormatBinaryData(uint32_t address, const uint8_t* data, size_t size,
                               const core::AddressMap* address_map) const;
  std::string FormatWordData(uint32_t address, const uint8_t* data, size_t size,
                             const core::AddressMap* address_map) const;
};

// Factory function
std::unique_ptr<Formatter> CreateEdtasmFormatter();

}  // namespace output
}  // namespace sourcerer

#endif  // SOURCERER_OUTPUT_EDTASM_FORMATTER_H_
