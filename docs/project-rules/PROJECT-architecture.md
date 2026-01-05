# Sourcerer Architecture Rules

> **Note:** This file contains Sourcerer-specific architectural patterns. For general SOLID principles and design patterns, see the shared standards (02-solid-principles.md, 01-design-principles.md).

## CPU-Agnostic Design (Critical)

The **most important architectural constraint** in Sourcerer is that analysis code must work with **any CPU architecture** without modification.

### The Golden Rule

**`CodeAnalyzer` and related analysis modules must NEVER contain CPU-specific logic.**

### What This Means

#### ✅ GOOD - CPU-Agnostic Pattern

```cpp
// CodeAnalyzer calls CPU plugin methods (abstractions)
class CodeAnalyzer {
public:
  void DiscoverEntryPoints() {
    // Get interrupt vectors from CPU (polymorphic)
    auto vectors = cpu_->GetInterruptVectors();
    for (const auto& vector : vectors) {
      uint32_t target = cpu_->ReadVectorTarget(data, size, vector.address);
      if (target != 0) {
        AddEntryPoint(target);
      }
    }

    // Check if regions look like code (delegates to CPU)
    for (uint32_t addr = start; addr < end; addr += alignment) {
      if (cpu_->IsLikelyCode(data, size, addr)) {
        AddEntryPoint(addr);
      }
    }
  }

private:
  CpuPlugin* cpu_;  // Abstraction, works with any CPU
};
```

#### ❌ BAD - CPU-Specific Logic

```cpp
// DON'T DO THIS - checking CPU variant and branching
void CodeAnalyzer::DiscoverEntryPoints() {
  if (cpu_->GetVariant() == CpuVariant::MOS_6502) {
    // 6502-specific logic here
    ScanVectorsAt(0xFFFA);  // 6502 NMI vector
  } else if (cpu_->GetVariant() == CpuVariant::MOTOROLA_6809) {
    // 6809-specific logic here
    ScanVectorsAt(0xFFF0);  // 6809 has different vectors
  }
  // This breaks Open/Closed Principle!
  // Adding Z80 support requires modifying this code!
}
```

### Why CPU-Agnostic Matters

1. **Open/Closed Principle:** Adding new CPUs doesn't require modifying analysis code
2. **Single Responsibility:** Analysis focuses on analysis, not CPU details
3. **Testability:** Can test analysis logic independently of specific CPUs
4. **Maintainability:** Changes to one CPU don't affect others

### How to Achieve CPU-Agnostic Design

**1. Define Abstract Methods in CpuPlugin**

When you need CPU-specific behavior, add a virtual method to `CpuPlugin`:

```cpp
// cpu/cpu_plugin.h
class CpuPlugin {
public:
  // NEW: Abstract method for CPU-specific behavior
  virtual bool LooksLikeSubroutineStart(
      const uint8_t* data, size_t size, uint32_t address) const {
    return false;  // Default implementation
  }
};
```

**2. Implement in Concrete CPU Classes**

Each CPU implements the behavior appropriately:

```cpp
// cpu/m6502/cpu_6502.cpp
bool Cpu6502::LooksLikeSubroutineStart(
    const uint8_t* data, size_t size, uint32_t address) const {
  // 6502-specific: look for PHP/PHA (stack frame setup)
  if (size < 2) return false;
  return (data[0] == 0x08 || data[0] == 0x48);  // PHP or PHA
}

// cpu/m6809/cpu_6809.cpp
bool Cpu6809::LooksLikeSubroutineStart(
    const uint8_t* data, size_t size, uint32_t address) const {
  // 6809-specific: look for PSHS (stack frame setup)
  if (size < 2) return false;
  return (data[0] == 0x34);  // PSHS
}
```

**3. Call Polymorphically in Analysis Code**

```cpp
// analysis/code_analyzer.cpp
void CodeAnalyzer::ScanForSubroutines() {
  for (uint32_t addr = start; addr < end; ++addr) {
    // Polymorphic call - works with any CPU
    if (cpu_->LooksLikeSubroutineStart(data, size, addr)) {
      discovered_entry_points_.insert(addr);
    }
  }
}
```

### Anti-Pattern Detection

If you see this in analysis code, **it's wrong**:

```cpp
// ❌ Checking variant
if (cpu_->GetVariant() == CpuVariant::MOS_6502) { /* ... */ }

// ❌ Downcasting to concrete type
auto* cpu_6502 = dynamic_cast<Cpu6502*>(cpu_);
if (cpu_6502 != nullptr) { /* ... */ }

// ❌ Including CPU-specific headers in analysis
#include "cpu/m6502/cpu_6502.h"  // Should only include cpu/cpu_plugin.h
```

## Plugin Architecture

Sourcerer uses the **Strategy Pattern** extensively for extensibility.

### Plugin Categories

1. **CPU Plugins** (`cpu::CpuPlugin`)
   - Handle CPU-specific instruction decoding
   - Provide analysis hints (interrupt vectors, code patterns)
   - Example: `Cpu6502`, `Cpu6809`

2. **Disk Extractors** (`disk::DiskExtractor`)
   - Extract binaries from disk images
   - Handle platform-specific disk formats
   - Example: `AcxExtractor`, `CocoExtractor`

3. **Output Formatters** (`output::Formatter`)
   - Generate assembler-specific syntax
   - Handle label formatting, directives
   - Example: `MerlinFormatter`, `EdtasmFormatter`

### Plugin Pattern Implementation

**1. Abstract Base Class (Interface)**

```cpp
// Define interface with pure virtual methods
class CpuPlugin {
public:
  virtual ~CpuPlugin() = default;

  virtual std::string Name() const = 0;
  virtual core::Instruction Disassemble(...) const = 0;
  // ... other interface methods
};
```

**2. Concrete Implementations**

```cpp
// Implement interface for specific CPU
class Cpu6502 : public CpuPlugin {
public:
  std::string Name() const override { return "6502"; }
  core::Instruction Disassemble(...) const override {
    // 6502-specific implementation
  }
};
```

**3. Factory Functions**

```cpp
// Factory creates concrete instances
std::unique_ptr<CpuPlugin> Create6502Plugin() {
  return std::make_unique<Cpu6502>(CpuVariant::MOS_6502);
}
```

**4. Registry for Runtime Discovery**

```cpp
// Register factories at program startup
namespace {
  bool registered_6502 = []() {
    CpuRegistry::Register("6502", Create6502Plugin);
    CpuRegistry::Register("65c02", Create65C02Plugin);
    return true;
  }();
}

// Client code creates plugins by name
auto cpu = CpuRegistry::Create("6502");
```

**5. Dependency Injection**

```cpp
// Inject plugin into components that use them
class CodeAnalyzer {
public:
  CodeAnalyzer(CpuPlugin* cpu, const Binary* binary)
    : cpu_(cpu), binary_(binary) {}

private:
  CpuPlugin* cpu_;  // Non-owning pointer (dependency)
  const Binary* binary_;
};
```

### Adding a New Plugin

**Example: Adding Z80 Support**

**Step 1:** Implement plugin interface

```cpp
// src/cpu/z80/cpu_z80.h
class CpuZ80 : public CpuPlugin {
public:
  std::string Name() const override;
  core::Instruction Disassemble(...) const override;
  // Implement all required methods
};
```

**Step 2:** Implement factory

```cpp
// src/cpu/z80/cpu_z80.cpp
std::unique_ptr<CpuPlugin> CreateZ80Plugin() {
  return std::make_unique<CpuZ80>();
}
```

**Step 3:** Register with registry

```cpp
// src/cpu/z80/cpu_z80.cpp
namespace {
  bool registered = []() {
    CpuRegistry::Register("z80", CreateZ80Plugin);
    return true;
  }();
}
```

**Step 4:** Done!

No changes needed to:
- `CodeAnalyzer` (already CPU-agnostic)
- `main.cpp` (uses registry)
- Other CPU plugins
- Analysis modules

### Plugin Benefits

- ✅ **Open/Closed Principle:** Add features without modifying existing code
- ✅ **Single Responsibility:** Each plugin handles one concern
- ✅ **Dependency Inversion:** High-level code depends on abstractions
- ✅ **Testability:** Easy to mock plugins for testing
- ✅ **Runtime Flexibility:** Choose plugins via command-line arguments

## Module Boundaries

### Clear Separation of Concerns

```
src/
├── core/          # Core data structures (Binary, Instruction, SymbolTable)
│   └── Depends on: nothing (foundation layer)
│
├── cpu/           # CPU plugins (decode instructions)
│   └── Depends on: core
│
├── disk/          # Disk extractors (load binaries from disk images)
│   └── Depends on: core
│
├── analysis/      # Code flow analysis (find code vs data)
│   └── Depends on: core, cpu
│
├── output/        # Output formatters (generate assembler syntax)
│   └── Depends on: core, analysis
│
└── utils/         # Utilities (logging, CLI parsing)
    └── Depends on: core
```

### Dependency Rules

1. **No circular dependencies** between modules
2. **Depend on abstractions** (interfaces, not concrete classes)
3. **Core module** has no dependencies (foundation)
4. **Analysis depends on CPU** but only via `CpuPlugin` interface

### Module Coupling

**Low coupling between modules:**

```cpp
// GOOD - depends on interface
#include "cpu/cpu_plugin.h"  // Abstract interface

class CodeAnalyzer {
  CpuPlugin* cpu_;  // Polymorphic reference
};

// BAD - depends on concrete implementation
#include "cpu/m6502/cpu_6502.h"  // Concrete class

class CodeAnalyzer {
  Cpu6502* cpu_;  // Tight coupling!
};
```

## Testing Strategy

### Plugin Testing

Each plugin has comprehensive unit tests:

```cpp
// tests/test_6502/test_cpu_6502.cpp
TEST(Cpu6502Test, DisassembleSimpleInstruction) {
  Cpu6502 cpu(CpuVariant::MOS_6502);
  uint8_t code[] = {0xA9, 0x42};  // LDA #$42

  auto inst = cpu.Disassemble(code, sizeof(code), 0x8000);

  EXPECT_EQ(inst.mnemonic, "LDA");
  EXPECT_EQ(inst.operand, "#$42");
  EXPECT_EQ(inst.mode, AddressingMode::IMMEDIATE);
}
```

### Integration Testing

Test plugins working together:

```cpp
// tests/test_integration/test_integration.cpp
TEST(IntegrationTest, DisassembleWithAnalysis) {
  // Setup
  auto cpu = Create6502Plugin();
  Binary binary = LoadTestBinary("test.bin", 0x8000);
  AddressMap address_map;

  // Execute
  CodeAnalyzer analyzer(cpu.get(), &binary);
  analyzer.Analyze(&address_map);

  // Verify
  EXPECT_TRUE(address_map.IsCode(0x8000));
  EXPECT_GT(analyzer.GetInstructionCount(), 0);
}
```

### Mock Plugins for Testing

Create mock plugins to test analysis independently:

```cpp
// Mock CPU plugin for testing
class MockCpuPlugin : public CpuPlugin {
public:
  MOCK_METHOD(core::Instruction, Disassemble, (...), (const, override));
  MOCK_METHOD(bool, IsLikelyCode, (...), (const, override));
  // ... other mocked methods
};

TEST(CodeAnalyzerTest, DiscoverEntryPoints) {
  MockCpuPlugin mock_cpu;
  EXPECT_CALL(mock_cpu, GetInterruptVectors())
    .WillOnce(Return(std::vector<InterruptVector>{{0xFFFC, "RESET"}}));

  // Test analyzer with mock
  CodeAnalyzer analyzer(&mock_cpu, &binary);
  // ...
}
```

## Common Architecture Mistakes

### ❌ Mistake 1: CPU-Specific Logic in Analysis

```cpp
// WRONG - analysis shouldn't know about specific CPUs
void CodeAnalyzer::Analyze() {
  if (cpu_->GetVariant() == CpuVariant::MOS_6502) {
    // 6502-specific analysis
  }
}
```

**Fix:** Add abstract method to `CpuPlugin`, implement in concrete CPUs.

### ❌ Mistake 2: Analysis Creating CPU Instances

```cpp
// WRONG - analysis shouldn't create CPUs
void CodeAnalyzer::Analyze() {
  auto cpu = std::make_unique<Cpu6502>();  // Violation of DIP!
  // ...
}
```

**Fix:** Inject CPU via constructor (dependency injection).

### ❌ Mistake 3: God Classes

```cpp
// WRONG - class doing too much
class Disassembler {
  void LoadBinary();         // File I/O
  void DecodeCpuInstructions();  // CPU-specific
  void AnalyzeCodeFlow();    // Analysis
  void GenerateOutput();     // Formatting
  // Violates Single Responsibility!
};
```

**Fix:** Split into focused classes (Binary, CpuPlugin, CodeAnalyzer, Formatter).

### ❌ Mistake 4: Tight Coupling

```cpp
// WRONG - Formatter depends on concrete CPU
class MerlinFormatter : public Formatter {
  Cpu6502* cpu_;  // Tight coupling!
};
```

**Fix:** Formatter shouldn't depend on CPU at all (only on Instruction).

## Architecture Review Checklist

Before committing, verify:

- ☐ **CPU-agnostic** - No CPU variant checks in analysis code
- ☐ **Plugin pattern** - Used for CPU, Disk, Formatter extensibility
- ☐ **Dependency injection** - Dependencies passed via constructor
- ☐ **No circular dependencies** - Clean module boundaries
- ☐ **Interface segregation** - Focused, cohesive interfaces
- ☐ **Testability** - Can mock dependencies
- ☐ **Open/Closed** - Can add features without modifying existing code

---

**This architecture enables Sourcerer to support multiple CPU families, disk formats, and output formats without modification to core analysis logic.**
