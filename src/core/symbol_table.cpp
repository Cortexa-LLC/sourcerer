// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "core/symbol_table.h"

#include <fstream>
#include <nlohmann/json.hpp>

#include "utils/logger.h"

namespace sourcerer {
namespace core {

using json = nlohmann::json;

SymbolTable::SymbolTable() {}

bool SymbolTable::LoadFromFile(const std::string& path) {
  LOG_INFO("Loading symbol table: " + path);

  std::ifstream file(path);
  if (!file) {
    LOG_ERROR("Failed to open symbol table file: " + path);
    return false;
  }

  std::string content((std::istreambuf_iterator<char>(file)),
                      std::istreambuf_iterator<char>());
  file.close();

  return LoadFromJson(content);
}

bool SymbolTable::LoadFromJson(const std::string& json_content) {
  try {
    json j = json::parse(json_content);

    // Get platform name
    std::string platform = j.value("platform", "unknown");
    LOG_DEBUG("Loading symbols for platform: " + platform);

    // Parse symbols array
    if (j.contains("symbols") && j["symbols"].is_array()) {
      for (const auto& sym : j["symbols"]) {
        Symbol symbol;

        // Parse address (support hex string or integer)
        if (sym["address"].is_string()) {
          std::string addr_str = sym["address"];
          if (addr_str.substr(0, 2) == "0x" || addr_str.substr(0, 1) == "$") {
            // Remove prefix
            if (addr_str[0] == '$') {
              addr_str = "0x" + addr_str.substr(1);
            }
            symbol.address = std::stoul(addr_str, nullptr, 16);
          } else {
            symbol.address = std::stoul(addr_str, nullptr, 0);
          }
        } else {
          symbol.address = sym["address"];
        }

        symbol.name = sym.value("name", "");
        symbol.symbol = sym.value("symbol", symbol.name);  // Default to name if not present
        symbol.description = sym.value("description", "");
        symbol.platform = platform;

        // Parse type
        std::string type_str = sym.value("type", "unknown");
        if (type_str == "io_port") {
          symbol.type = SymbolType::IO_PORT;
        } else if (type_str == "rom_routine" || type_str == "routine") {
          symbol.type = SymbolType::ROM_ROUTINE;
        } else if (type_str == "zero_page") {
          symbol.type = SymbolType::ZERO_PAGE;
        } else if (type_str == "system_variable") {
          symbol.type = SymbolType::SYSTEM_VARIABLE;
        } else if (type_str == "soft_switch") {
          symbol.type = SymbolType::SOFT_SWITCH;
        } else if (type_str == "hardware") {
          symbol.type = SymbolType::HARDWARE;
        } else if (type_str == "mli_call") {
          symbol.type = SymbolType::MLI_CALL;
        } else {
          symbol.type = SymbolType::UNKNOWN;
        }

        AddSymbol(symbol);
      }

      LOG_INFO("Loaded " + std::to_string(symbols_.size()) + " symbols");
      return true;
    }

    LOG_WARNING("No symbols found in JSON");
    return false;

  } catch (const json::exception& e) {
    LOG_ERROR("JSON parse error: " + std::string(e.what()));
    return false;
  }
}

void SymbolTable::AddSymbol(const Symbol& symbol) {
  Symbol s = symbol;
  // Default symbol field to name if not set (assembler-safe name)
  if (s.symbol.empty()) {
    s.symbol = s.name;
  }
  symbols_[s.address] = s;
}

void SymbolTable::AddSymbol(uint32_t address, const std::string& name,
                            SymbolType type, const std::string& description,
                            const std::string& platform) {
  Symbol symbol;
  symbol.address = address;
  symbol.name = name;
  symbol.symbol = name;  // Default to name
  symbol.type = type;
  symbol.description = description;
  symbol.platform = platform;
  AddSymbol(symbol);
}

bool SymbolTable::HasSymbol(uint32_t address) const {
  return symbols_.find(address) != symbols_.end();
}

std::optional<Symbol> SymbolTable::GetSymbol(uint32_t address) const {
  auto it = symbols_.find(address);
  if (it != symbols_.end()) {
    return it->second;
  }
  return std::nullopt;
}

std::optional<std::string> SymbolTable::GetSymbolName(uint32_t address) const {
  auto it = symbols_.find(address);
  if (it != symbols_.end()) {
    // Return symbol field (assembler-safe name), which defaults to name if not set
    return it->second.symbol;
  }
  return std::nullopt;
}

std::vector<Symbol> SymbolTable::GetSymbolsByPlatform(
    const std::string& platform) const {
  std::vector<Symbol> result;
  for (const auto& pair : symbols_) {
    if (pair.second.platform == platform) {
      result.push_back(pair.second);
    }
  }
  return result;
}

void SymbolTable::Clear() {
  symbols_.clear();
}

}  // namespace core
}  // namespace sourcerer
