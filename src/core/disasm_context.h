// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_CORE_DISASM_CONTEXT_H_
#define SOURCERER_CORE_DISASM_CONTEXT_H_

#include <memory>
#include <string>

#include "core/address_map.h"
#include "core/binary.h"
#include "core/symbol_table.h"

namespace sourcerer {
namespace core {

// Disassembly session state and configuration
class DisasmContext {
 public:
  DisasmContext();
  explicit DisasmContext(const Binary& binary);

  // Binary accessors
  const Binary& binary() const { return binary_; }
  void set_binary(const Binary& binary) { binary_ = binary; }

  // Address map accessors
  AddressMap& address_map() { return address_map_; }
  const AddressMap& address_map() const { return address_map_; }

  // Symbol table accessors
  SymbolTable& symbol_table() { return symbol_table_; }
  const SymbolTable& symbol_table() const { return symbol_table_; }

  // CPU type
  const std::string& cpu_type() const { return cpu_type_; }
  void set_cpu_type(const std::string& type) { cpu_type_ = type; }

  // Output format
  const std::string& output_format() const { return output_format_; }
  void set_output_format(const std::string& format) { output_format_ = format; }

  // Entry point (defaults to load address)
  uint32_t entry_point() const { return entry_point_; }
  void set_entry_point(uint32_t address) { entry_point_ = address; }

  // Options
  bool enable_analysis() const { return enable_analysis_; }
  void set_enable_analysis(bool enable) { enable_analysis_ = enable; }

  bool generate_labels() const { return generate_labels_; }
  void set_generate_labels(bool enable) { generate_labels_ = enable; }

  bool generate_xrefs() const { return generate_xrefs_; }
  void set_generate_xrefs(bool enable) { generate_xrefs_ = enable; }

  bool verbose() const { return verbose_; }
  void set_verbose(bool enable) { verbose_ = enable; }

 private:
  Binary binary_;
  AddressMap address_map_;
  SymbolTable symbol_table_;
  std::string cpu_type_;
  std::string output_format_;
  uint32_t entry_point_;
  bool enable_analysis_;
  bool generate_labels_;
  bool generate_xrefs_;
  bool verbose_;
};

}  // namespace core
}  // namespace sourcerer

#endif  // SOURCERER_CORE_DISASM_CONTEXT_H_
