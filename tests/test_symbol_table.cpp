// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "core/symbol_table.h"

#include <gtest/gtest.h>

#include <fstream>

namespace sourcerer {
namespace core {
namespace {

// Test fixture for SymbolTable class
class SymbolTableTest : public ::testing::Test {
 protected:
  void SetUp() override {
    table_ = std::make_unique<SymbolTable>();
  }

  std::unique_ptr<SymbolTable> table_;
};

// Test default constructor
TEST_F(SymbolTableTest, DefaultConstructor) {
  EXPECT_EQ(table_->GetSymbolCount(), 0);
  EXPECT_TRUE(table_->GetAllSymbols().empty());
}

// Test AddSymbol with Symbol struct
TEST_F(SymbolTableTest, AddSymbolStruct) {
  Symbol sym;
  sym.address = 0xC000;
  sym.name = "KEYBOARD";
  sym.symbol = "KBD";
  sym.type = SymbolType::IO_PORT;
  sym.description = "Keyboard input register";
  sym.platform = "apple2e";

  table_->AddSymbol(sym);

  EXPECT_EQ(table_->GetSymbolCount(), 1);
  EXPECT_TRUE(table_->HasSymbol(0xC000));

  auto retrieved = table_->GetSymbol(0xC000);
  ASSERT_TRUE(retrieved.has_value());
  EXPECT_EQ(retrieved->address, 0xC000);
  EXPECT_EQ(retrieved->name, "KEYBOARD");
  EXPECT_EQ(retrieved->symbol, "KBD");
  EXPECT_EQ(retrieved->type, SymbolType::IO_PORT);
  EXPECT_EQ(retrieved->description, "Keyboard input register");
  EXPECT_EQ(retrieved->platform, "apple2e");
}

// Test AddSymbol with parameters
TEST_F(SymbolTableTest, AddSymbolParameters) {
  table_->AddSymbol(0xFF00, "SWI_VECTOR", SymbolType::ROM_ROUTINE,
                    "Software interrupt vector", "coco");

  EXPECT_EQ(table_->GetSymbolCount(), 1);
  EXPECT_TRUE(table_->HasSymbol(0xFF00));

  auto sym = table_->GetSymbol(0xFF00);
  ASSERT_TRUE(sym.has_value());
  EXPECT_EQ(sym->address, 0xFF00);
  EXPECT_EQ(sym->name, "SWI_VECTOR");
  EXPECT_EQ(sym->symbol, "SWI_VECTOR");  // Defaults to name
  EXPECT_EQ(sym->type, SymbolType::ROM_ROUTINE);
  EXPECT_EQ(sym->description, "Software interrupt vector");
  EXPECT_EQ(sym->platform, "coco");
}

// Test AddSymbol with defaults
TEST_F(SymbolTableTest, AddSymbolDefaults) {
  table_->AddSymbol(0x8000, "START");

  auto sym = table_->GetSymbol(0x8000);
  ASSERT_TRUE(sym.has_value());
  EXPECT_EQ(sym->address, 0x8000);
  EXPECT_EQ(sym->name, "START");
  EXPECT_EQ(sym->symbol, "START");
  EXPECT_EQ(sym->type, SymbolType::UNKNOWN);
  EXPECT_TRUE(sym->description.empty());
  EXPECT_TRUE(sym->platform.empty());
}

// Test symbol field defaulting to name
TEST_F(SymbolTableTest, SymbolFieldDefaultsToName) {
  Symbol sym;
  sym.address = 0x0000;
  sym.name = "ZERO_PAGE_START";
  sym.symbol = "";  // Empty
  sym.type = SymbolType::ZERO_PAGE;

  table_->AddSymbol(sym);

  auto retrieved = table_->GetSymbol(0x0000);
  ASSERT_TRUE(retrieved.has_value());
  EXPECT_EQ(retrieved->symbol, "ZERO_PAGE_START");  // Should default to name
}

// Test GetSymbolName
TEST_F(SymbolTableTest, GetSymbolName) {
  Symbol sym;
  sym.address = 0xC000;
  sym.name = "KEYBOARD";
  sym.symbol = "KBD";
  sym.type = SymbolType::IO_PORT;

  table_->AddSymbol(sym);

  auto name = table_->GetSymbolName(0xC000);
  ASSERT_TRUE(name.has_value());
  EXPECT_EQ(*name, "KBD");  // Returns symbol field, not name
}

// Test GetSymbolName when symbol not found
TEST_F(SymbolTableTest, GetSymbolNameNotFound) {
  auto name = table_->GetSymbolName(0x9999);
  EXPECT_FALSE(name.has_value());
}

// Test HasSymbol
TEST_F(SymbolTableTest, HasSymbol) {
  EXPECT_FALSE(table_->HasSymbol(0x8000));

  table_->AddSymbol(0x8000, "START");
  EXPECT_TRUE(table_->HasSymbol(0x8000));
  EXPECT_FALSE(table_->HasSymbol(0x8001));
}

// Test GetSymbol when not found
TEST_F(SymbolTableTest, GetSymbolNotFound) {
  auto sym = table_->GetSymbol(0x9999);
  EXPECT_FALSE(sym.has_value());
}

// Test multiple symbols
TEST_F(SymbolTableTest, MultipleSymbols) {
  table_->AddSymbol(0x8000, "START", SymbolType::ROM_ROUTINE);
  table_->AddSymbol(0x8010, "INIT", SymbolType::ROM_ROUTINE);
  table_->AddSymbol(0xC000, "KEYBOARD", SymbolType::IO_PORT);

  EXPECT_EQ(table_->GetSymbolCount(), 3);
  EXPECT_TRUE(table_->HasSymbol(0x8000));
  EXPECT_TRUE(table_->HasSymbol(0x8010));
  EXPECT_TRUE(table_->HasSymbol(0xC000));
}

// Test symbol overwrite
TEST_F(SymbolTableTest, SymbolOverwrite) {
  table_->AddSymbol(0x8000, "START", SymbolType::UNKNOWN);
  EXPECT_EQ(table_->GetSymbolCount(), 1);

  auto sym = table_->GetSymbol(0x8000);
  ASSERT_TRUE(sym.has_value());
  EXPECT_EQ(sym->name, "START");
  EXPECT_EQ(sym->type, SymbolType::UNKNOWN);

  // Overwrite with new symbol
  table_->AddSymbol(0x8000, "ENTRY_POINT", SymbolType::ROM_ROUTINE);
  EXPECT_EQ(table_->GetSymbolCount(), 1);  // Still 1 symbol

  sym = table_->GetSymbol(0x8000);
  ASSERT_TRUE(sym.has_value());
  EXPECT_EQ(sym->name, "ENTRY_POINT");
  EXPECT_EQ(sym->type, SymbolType::ROM_ROUTINE);
}

// Test GetSymbolsByPlatform
TEST_F(SymbolTableTest, GetSymbolsByPlatform) {
  table_->AddSymbol(0x8000, "COCO_START", SymbolType::ROM_ROUTINE, "", "coco");
  table_->AddSymbol(0x8010, "COCO_INIT", SymbolType::ROM_ROUTINE, "", "coco");
  table_->AddSymbol(0xC000, "APPLE_KBD", SymbolType::IO_PORT, "", "apple2e");
  table_->AddSymbol(0xC010, "APPLE_STROBE", SymbolType::IO_PORT, "", "apple2e");

  auto coco_symbols = table_->GetSymbolsByPlatform("coco");
  EXPECT_EQ(coco_symbols.size(), 2);
  EXPECT_EQ(coco_symbols[0].name, "COCO_START");
  EXPECT_EQ(coco_symbols[1].name, "COCO_INIT");

  auto apple_symbols = table_->GetSymbolsByPlatform("apple2e");
  EXPECT_EQ(apple_symbols.size(), 2);
  EXPECT_EQ(apple_symbols[0].name, "APPLE_KBD");
  EXPECT_EQ(apple_symbols[1].name, "APPLE_STROBE");

  auto c64_symbols = table_->GetSymbolsByPlatform("c64");
  EXPECT_TRUE(c64_symbols.empty());
}

// Test Clear
TEST_F(SymbolTableTest, Clear) {
  table_->AddSymbol(0x8000, "START");
  table_->AddSymbol(0x8010, "INIT");
  table_->AddSymbol(0xC000, "KEYBOARD");

  EXPECT_EQ(table_->GetSymbolCount(), 3);

  table_->Clear();

  EXPECT_EQ(table_->GetSymbolCount(), 0);
  EXPECT_FALSE(table_->HasSymbol(0x8000));
  EXPECT_FALSE(table_->HasSymbol(0x8010));
  EXPECT_FALSE(table_->HasSymbol(0xC000));
}

// Test all SymbolTypes
TEST_F(SymbolTableTest, AllSymbolTypes) {
  table_->AddSymbol(0x0000, "ZP_VAR", SymbolType::ZERO_PAGE);
  table_->AddSymbol(0x8000, "ROM_FUNC", SymbolType::ROM_ROUTINE);
  table_->AddSymbol(0xC000, "IO_PORT", SymbolType::IO_PORT);
  table_->AddSymbol(0xC010, "SYS_VAR", SymbolType::SYSTEM_VARIABLE);
  table_->AddSymbol(0xC030, "SOFT_SW", SymbolType::SOFT_SWITCH);
  table_->AddSymbol(0xC080, "HW_REG", SymbolType::HARDWARE);
  table_->AddSymbol(0xBF00, "MLI_CALL", SymbolType::MLI_CALL);
  table_->AddSymbol(0x9000, "UNKNOWN", SymbolType::UNKNOWN);

  EXPECT_EQ(table_->GetSymbol(0x0000)->type, SymbolType::ZERO_PAGE);
  EXPECT_EQ(table_->GetSymbol(0x8000)->type, SymbolType::ROM_ROUTINE);
  EXPECT_EQ(table_->GetSymbol(0xC000)->type, SymbolType::IO_PORT);
  EXPECT_EQ(table_->GetSymbol(0xC010)->type, SymbolType::SYSTEM_VARIABLE);
  EXPECT_EQ(table_->GetSymbol(0xC030)->type, SymbolType::SOFT_SWITCH);
  EXPECT_EQ(table_->GetSymbol(0xC080)->type, SymbolType::HARDWARE);
  EXPECT_EQ(table_->GetSymbol(0xBF00)->type, SymbolType::MLI_CALL);
  EXPECT_EQ(table_->GetSymbol(0x9000)->type, SymbolType::UNKNOWN);
}

// Test LoadFromJson - valid JSON
TEST_F(SymbolTableTest, LoadFromJsonValid) {
  std::string json = R"({
    "platform": "test_platform",
    "symbols": [
      {
        "address": "0xC000",
        "name": "KEYBOARD",
        "symbol": "KBD",
        "type": "io_port",
        "description": "Keyboard input"
      },
      {
        "address": "$FF00",
        "name": "SWI_VECTOR",
        "type": "rom_routine",
        "description": "SWI handler"
      }
    ]
  })";

  EXPECT_TRUE(table_->LoadFromJson(json));
  EXPECT_EQ(table_->GetSymbolCount(), 2);

  auto kbd = table_->GetSymbol(0xC000);
  ASSERT_TRUE(kbd.has_value());
  EXPECT_EQ(kbd->name, "KEYBOARD");
  EXPECT_EQ(kbd->symbol, "KBD");
  EXPECT_EQ(kbd->type, SymbolType::IO_PORT);
  EXPECT_EQ(kbd->platform, "test_platform");

  auto swi = table_->GetSymbol(0xFF00);
  ASSERT_TRUE(swi.has_value());
  EXPECT_EQ(swi->name, "SWI_VECTOR");
  EXPECT_EQ(swi->type, SymbolType::ROM_ROUTINE);
}

// Test LoadFromJson - integer address
TEST_F(SymbolTableTest, LoadFromJsonIntegerAddress) {
  std::string json = R"({
    "platform": "test",
    "symbols": [
      {
        "address": 49152,
        "name": "KEYBOARD",
        "type": "io_port"
      }
    ]
  })";

  EXPECT_TRUE(table_->LoadFromJson(json));
  EXPECT_TRUE(table_->HasSymbol(0xC000));  // 49152 = 0xC000
}

// Test LoadFromJson - all symbol types
TEST_F(SymbolTableTest, LoadFromJsonAllTypes) {
  std::string json = R"({
    "platform": "test",
    "symbols": [
      {"address": "0x0000", "name": "ZP", "type": "zero_page"},
      {"address": "0x0001", "name": "ROM", "type": "rom_routine"},
      {"address": "0x0002", "name": "ROM2", "type": "routine"},
      {"address": "0x0003", "name": "IO", "type": "io_port"},
      {"address": "0x0004", "name": "SYS", "type": "system_variable"},
      {"address": "0x0005", "name": "SW", "type": "soft_switch"},
      {"address": "0x0006", "name": "HW", "type": "hardware"},
      {"address": "0x0007", "name": "MLI", "type": "mli_call"},
      {"address": "0x0008", "name": "UNK", "type": "unknown"},
      {"address": "0x0009", "name": "BAD", "type": "invalid_type"}
    ]
  })";

  EXPECT_TRUE(table_->LoadFromJson(json));
  EXPECT_EQ(table_->GetSymbolCount(), 10);

  EXPECT_EQ(table_->GetSymbol(0x0000)->type, SymbolType::ZERO_PAGE);
  EXPECT_EQ(table_->GetSymbol(0x0001)->type, SymbolType::ROM_ROUTINE);
  EXPECT_EQ(table_->GetSymbol(0x0002)->type, SymbolType::ROM_ROUTINE);  // "routine" alias
  EXPECT_EQ(table_->GetSymbol(0x0003)->type, SymbolType::IO_PORT);
  EXPECT_EQ(table_->GetSymbol(0x0004)->type, SymbolType::SYSTEM_VARIABLE);
  EXPECT_EQ(table_->GetSymbol(0x0005)->type, SymbolType::SOFT_SWITCH);
  EXPECT_EQ(table_->GetSymbol(0x0006)->type, SymbolType::HARDWARE);
  EXPECT_EQ(table_->GetSymbol(0x0007)->type, SymbolType::MLI_CALL);
  EXPECT_EQ(table_->GetSymbol(0x0008)->type, SymbolType::UNKNOWN);
  EXPECT_EQ(table_->GetSymbol(0x0009)->type, SymbolType::UNKNOWN);  // Invalid type -> UNKNOWN
}

// Test LoadFromJson - symbol field defaults to name
TEST_F(SymbolTableTest, LoadFromJsonSymbolDefaultsToName) {
  std::string json = R"({
    "platform": "test",
    "symbols": [
      {
        "address": "0xC000",
        "name": "KEYBOARD",
        "type": "io_port"
      }
    ]
  })";

  EXPECT_TRUE(table_->LoadFromJson(json));

  auto sym = table_->GetSymbol(0xC000);
  ASSERT_TRUE(sym.has_value());
  EXPECT_EQ(sym->symbol, "KEYBOARD");  // Should default to name
}

// Test LoadFromJson - invalid JSON
TEST_F(SymbolTableTest, LoadFromJsonInvalid) {
  std::string json = "{ invalid json }";
  EXPECT_FALSE(table_->LoadFromJson(json));
  EXPECT_EQ(table_->GetSymbolCount(), 0);
}

// Test LoadFromJson - missing symbols array
TEST_F(SymbolTableTest, LoadFromJsonNoSymbols) {
  std::string json = R"({
    "platform": "test"
  })";

  EXPECT_FALSE(table_->LoadFromJson(json));
  EXPECT_EQ(table_->GetSymbolCount(), 0);
}

// Test LoadFromJson - empty symbols array
TEST_F(SymbolTableTest, LoadFromJsonEmptySymbols) {
  std::string json = R"({
    "platform": "test",
    "symbols": []
  })";

  // Empty symbols array is still valid JSON, returns true with 0 symbols
  EXPECT_TRUE(table_->LoadFromJson(json));
  EXPECT_EQ(table_->GetSymbolCount(), 0);
}

// Test LoadFromJson - symbols not an array
TEST_F(SymbolTableTest, LoadFromJsonSymbolsNotArray) {
  std::string json = R"({
    "platform": "test",
    "symbols": "not an array"
  })";

  EXPECT_FALSE(table_->LoadFromJson(json));
  EXPECT_EQ(table_->GetSymbolCount(), 0);
}

// Test LoadFromFile - file not found
TEST_F(SymbolTableTest, LoadFromFileNotFound) {
  EXPECT_FALSE(table_->LoadFromFile("/nonexistent/path/symbols.json"));
  EXPECT_EQ(table_->GetSymbolCount(), 0);
}

// Test LoadFromFile - valid file
TEST_F(SymbolTableTest, LoadFromFileValid) {
  // Create temporary test file
  const std::string temp_file = "/tmp/test_symbols.json";
  std::ofstream out(temp_file);
  out << R"({
    "platform": "test",
    "symbols": [
      {
        "address": "0xC000",
        "name": "KEYBOARD",
        "type": "io_port"
      }
    ]
  })";
  out.close();

  EXPECT_TRUE(table_->LoadFromFile(temp_file));
  EXPECT_EQ(table_->GetSymbolCount(), 1);
  EXPECT_TRUE(table_->HasSymbol(0xC000));

  // Clean up
  std::remove(temp_file.c_str());
}

// Test GetAllSymbols
TEST_F(SymbolTableTest, GetAllSymbols) {
  table_->AddSymbol(0x8000, "START");
  table_->AddSymbol(0x8010, "INIT");
  table_->AddSymbol(0xC000, "KEYBOARD");

  const auto& symbols = table_->GetAllSymbols();
  EXPECT_EQ(symbols.size(), 3);
  EXPECT_TRUE(symbols.find(0x8000) != symbols.end());
  EXPECT_TRUE(symbols.find(0x8010) != symbols.end());
  EXPECT_TRUE(symbols.find(0xC000) != symbols.end());
}

// Test address boundaries
TEST_F(SymbolTableTest, AddressBoundaries) {
  // Zero page
  table_->AddSymbol(0x0000, "ZERO");
  EXPECT_TRUE(table_->HasSymbol(0x0000));

  // 16-bit max
  table_->AddSymbol(0xFFFF, "MAX_16");
  EXPECT_TRUE(table_->HasSymbol(0xFFFF));

  // 32-bit address (for future CPUs)
  table_->AddSymbol(0x12345678, "LONG_ADDR");
  EXPECT_TRUE(table_->HasSymbol(0x12345678));
}

// Test comprehensive scenario
TEST_F(SymbolTableTest, ComprehensiveScenario) {
  // Load from JSON
  std::string json = R"({
    "platform": "apple2e",
    "symbols": [
      {"address": "0xC000", "name": "KEYBOARD", "symbol": "KBD", "type": "io_port"},
      {"address": "0xC010", "name": "KBDSTRB", "type": "io_port"},
      {"address": "0xFDED", "name": "COUT", "type": "rom_routine"}
    ]
  })";

  EXPECT_TRUE(table_->LoadFromJson(json));
  EXPECT_EQ(table_->GetSymbolCount(), 3);

  // Add more symbols
  table_->AddSymbol(0x8000, "PROGRAM_START", SymbolType::ROM_ROUTINE, "", "custom");
  EXPECT_EQ(table_->GetSymbolCount(), 4);

  // Query by platform
  auto apple_symbols = table_->GetSymbolsByPlatform("apple2e");
  EXPECT_EQ(apple_symbols.size(), 3);

  auto custom_symbols = table_->GetSymbolsByPlatform("custom");
  EXPECT_EQ(custom_symbols.size(), 1);

  // Get specific symbols
  auto kbd = table_->GetSymbolName(0xC000);
  ASSERT_TRUE(kbd.has_value());
  EXPECT_EQ(*kbd, "KBD");

  auto cout = table_->GetSymbol(0xFDED);
  ASSERT_TRUE(cout.has_value());
  EXPECT_EQ(cout->type, SymbolType::ROM_ROUTINE);

  // Clear and verify
  table_->Clear();
  EXPECT_EQ(table_->GetSymbolCount(), 0);
}

}  // namespace
}  // namespace core
}  // namespace sourcerer
