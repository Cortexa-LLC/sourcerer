// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_CORE_SYMBOL_TABLE_H_
#define SOURCERER_CORE_SYMBOL_TABLE_H_

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace sourcerer {
namespace core {

// Symbol types for memory-mapped locations
enum class SymbolType {
  UNKNOWN,
  IO_PORT,           // Memory-mapped I/O (e.g., $C000 = KEYBOARD)
  ROM_ROUTINE,       // ROM subroutine entry point
  ZERO_PAGE,         // Zero page variable/pointer
  SYSTEM_VARIABLE,   // OS/system variable
  SOFT_SWITCH,       // Hardware soft switch
  HARDWARE,          // Hardware register
  MLI_CALL,          // OS MLI/API call number
};

// Symbol definition
struct Symbol {
  uint32_t address;
  std::string name;
  SymbolType type;
  std::string description;
  std::string platform;  // e.g., "apple2e", "prodos8", "c64"
};

// Symbol table manager
class SymbolTable {
 public:
  SymbolTable();

  // Load symbols from JSON file
  bool LoadFromFile(const std::string& path);

  // Load symbols from JSON string
  bool LoadFromJson(const std::string& json_content);

  // Add a symbol manually
  void AddSymbol(const Symbol& symbol);
  void AddSymbol(uint32_t address, const std::string& name,
                 SymbolType type = SymbolType::UNKNOWN,
                 const std::string& description = "",
                 const std::string& platform = "");

  // Query symbols
  bool HasSymbol(uint32_t address) const;
  Symbol GetSymbol(uint32_t address) const;
  std::string GetSymbolName(uint32_t address) const;

  // Get all symbols for a platform
  std::vector<Symbol> GetSymbolsByPlatform(const std::string& platform) const;

  // Get all symbols
  const std::map<uint32_t, Symbol>& GetAllSymbols() const { return symbols_; }

  // Clear all symbols
  void Clear();

  // Get count
  size_t GetSymbolCount() const { return symbols_.size(); }

 private:
  std::map<uint32_t, Symbol> symbols_;
};

}  // namespace core
}  // namespace sourcerer

#endif  // SOURCERER_CORE_SYMBOL_TABLE_H_
