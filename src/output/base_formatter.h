// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_OUTPUT_BASE_FORMATTER_H_
#define SOURCERER_OUTPUT_BASE_FORMATTER_H_

#include <memory>
#include <string>
#include <vector>

#include "output/formatter.h"

namespace sourcerer {
namespace output {

// Forward declarations
class DataCollector;
class AddressAnalyzer;
class LabelResolver;

// Base formatter implementing Template Method pattern
// Eliminates ~500 lines of duplication across formatter implementations
class BaseFormatter : public Formatter {
 public:
  BaseFormatter();
  ~BaseFormatter() override;  // Must be defined in .cpp due to incomplete types in unique_ptr

  // Formatter interface - final implementations (Template Method pattern)
  std::string Format(const core::Binary& binary,
                    const std::vector<core::Instruction>& instructions,
                    const core::AddressMap* address_map = nullptr,
                    const core::SymbolTable* symbol_table = nullptr,
                    const analysis::EquateGenerator* equate_gen = nullptr) final;

  std::string FormatInstruction(
      const core::Instruction& inst,
      const core::AddressMap* address_map = nullptr,
      const core::SymbolTable* symbol_table = nullptr,
      const analysis::EquateGenerator* equate_gen = nullptr) final;

  std::string FormatData(uint32_t address,
                        const std::vector<uint8_t>& bytes) final;

  std::string FormatHeader(const core::Binary& binary) final;

  std::string FormatFooter() final;

 protected:
  // Template methods - subclasses must implement these

  // Assembler directives
  virtual std::string GetEquateDirective() const = 0;  // "EQU" or ".EQ"
  virtual std::string GetOrgDirective() const = 0;     // "ORG" or ".OR"
  virtual std::string GetByteDirective() const = 0;    // "FCB", "DFB", ".DA"
  virtual std::string GetWordDirective() const = 0;    // "FDB", "DA", ".DA"
  virtual std::string GetStringDirective() const = 0;  // "FCC", "ASC"
  virtual std::string GetEndDirective() const = 0;     // "END", "", ".TF"

  // Comment style
  virtual std::string GetCommentPrefix() const = 0;    // "; ", ""

  // Column positions
  virtual int GetLabelColumn() const { return 0; }
  virtual int GetOpcodeColumn() const = 0;
  virtual int GetOperandColumn() const { return GetOpcodeColumn() + 6; }
  virtual int GetCommentColumn() const = 0;

  // Hook methods - optional overrides for format-specific behavior
  virtual std::string FormatHeaderContent(const core::Binary& binary);
  virtual std::string FormatFooterContent();
  virtual bool RequiresLineNumbers() const { return false; }
  virtual std::string AddLineNumbers(const std::string& text) const;

  // Format-specific customization points
  virtual std::string FormatDataRegionCustom(
      uint32_t address,
      const std::vector<uint8_t>& bytes,
      const core::AddressMap* address_map,
      const core::SymbolTable* symbol_table,
      const core::Binary* binary);

  virtual std::string GenerateBranchCommentCustom(
      const std::string& mnemonic) const;

  virtual std::string GenerateSemanticCommentCustom(
      const core::Instruction& inst,
      const core::SymbolTable* symbol_table) const;

 private:
  // Common implementations (DRY - Don't Repeat Yourself)

  // EQU statement generation (identical across all formatters)
  std::string FormatEquates(
      const std::set<uint32_t>& referenced_addresses,
      const core::SymbolTable* symbol_table,
      const analysis::EquateGenerator* equate_gen);

  // Address formatting
  std::string FormatAddress(uint32_t address, int width) const;

  // Label resolution
  std::string GetLabel(uint32_t address,
                      const core::AddressMap* address_map) const;

  bool IsSubroutineLabel(const std::string& label) const;

  // Data formatting helpers
  std::string FormatStringData(uint32_t address,
                               const uint8_t* data,
                               size_t size,
                               const core::AddressMap* address_map) const;

  std::string FormatBinaryData(uint32_t address,
                               const uint8_t* data,
                               size_t size,
                               const core::AddressMap* address_map) const;

  // Format multi-line comments with proper comment prefix on each line
  void WriteMultiLineComment(std::ostream& out,
                             const std::string& comment,
                             int indent_column) const;

  std::string FormatWordData(uint32_t address,
                             const uint8_t* data,
                             size_t size,
                             const core::AddressMap* address_map) const;

  bool IsStringData(const uint8_t* data, size_t size) const;

  // Instruction comment generation
  std::string GenerateInstructionComment(
      const core::Instruction& inst,
      const core::AddressMap* address_map,
      const core::SymbolTable* symbol_table) const;

  std::string GenerateBranchComment(const std::string& mnemonic) const;

  std::string GenerateSemanticComment(
      const core::Instruction& inst,
      const core::SymbolTable* symbol_table) const;

  std::string GetPlatformHint(const std::string& operand,
                              const core::SymbolTable* symbol_table) const;

  bool IsPlatformRegister(const std::string& symbol) const;

  // Format a complete data region (CODE/DATA interleaving)
  std::string FormatDataRegion(uint32_t address,
                               const std::vector<uint8_t>& bytes,
                               const core::AddressMap* address_map,
                               const core::SymbolTable* symbol_table,
                               const core::Binary* binary);

  // Component helpers (shared state during formatting)
  std::unique_ptr<DataCollector> data_collector_;
  std::unique_ptr<AddressAnalyzer> address_analyzer_;
  std::unique_ptr<LabelResolver> label_resolver_;
};

}  // namespace output
}  // namespace sourcerer

#endif  // SOURCERER_OUTPUT_BASE_FORMATTER_H_
