# Sourcerer Project Rules

> **Note:** This file contains Sourcerer-specific conventions. For general principles (SOLID, design patterns, C++ guidelines), see the shared standards without the `PROJECT-` prefix.

## Formatting (Critical)

### Indentation and Spacing
- ✅ **NO TABS** - Use spaces only
- ✅ **2-space indentation** (not 4-space)
- ✅ No trailing whitespace
- ✅ Unix line endings (LF, not CRLF)
- ✅ Files end with single newline

### Line Length
- ✅ **Soft limit:** 100 characters
- ✅ **Hard limit:** 120 characters (never exceed)
- Break long lines logically at operators, parameters, or method chains

### Example

```cpp
// GOOD - 2-space indentation, clear breaks
void Cpu6502::DisassembleLongInstruction(
    const uint8_t* data, size_t size, uint32_t address,
    std::vector<core::Instruction>* instructions) {
  if (data == nullptr || size == 0) {
    return;
  }
  // ...
}

// BAD - tabs, 4-space, too long
void Cpu6502::DisassembleLongInstruction(const uint8_t* data, size_t size, uint32_t address, std::vector<core::Instruction>* instructions) {
    if (data == nullptr || size == 0) {  // Tab used!
        return;
    }
}
```

## Naming Conventions

Follow **Google C++ Style Guide** conventions:

### Classes and Structs
- `PascalCase` for types
- Clear, descriptive names

```cpp
class CodeAnalyzer { /* ... */ };
class Cpu6502 { /* ... */ };
struct Instruction { /* ... */ };
struct JumpTableCandidate { /* ... */ };
```

### Functions and Methods
- `PascalCase` for functions (Google style)
- Verb-based names for actions
- Question-based names for predicates

```cpp
void Analyze();                    // Action
bool IsValidAddress();             // Predicate
core::Instruction Disassemble();   // Action returning value
uint32_t GetLoadAddress() const;   // Getter
```

### Variables
- `snake_case` for variables
- `snake_case_` with trailing underscore for private members

```cpp
// Local variables
uint32_t load_address = 0x8000;
std::vector<uint8_t> data_buffer;

// Member variables
class Binary {
private:
  std::vector<uint8_t> data_;        // Trailing underscore
  uint32_t load_address_;
  std::string source_file_;
};
```

### Constants
- `UPPER_CASE` for preprocessor macros and enum values
- `kPascalCase` for const variables (Google style)

```cpp
#define MAX_INSTRUCTIONS 100000         // Preprocessor (avoid if possible)

const int kDefaultBufferSize = 1024;    // Google style
constexpr size_t kMaxRecursionDepth = 1000;

enum class AddressingMode {
  UNKNOWN,           // ALL_CAPS for enumerators
  IMMEDIATE,
  ABSOLUTE,
};
```

### Namespaces
- `lowercase` for namespaces
- Match directory structure

```cpp
namespace sourcerer {
namespace core {
namespace cpu {
namespace m6502 {
```

### Files
- `snake_case.cpp` and `snake_case.h`
- Match class name in snake_case

```cpp
// Files: code_analyzer.h, code_analyzer.cpp
class CodeAnalyzer { /* ... */ };

// Files: cpu_6502.h, cpu_6502.cpp
class Cpu6502 { /* ... */ };
```

## Include Guards

Use header guards with full path in uppercase:

```cpp
#ifndef SOURCERER_MODULE_FILENAME_H_
#define SOURCERER_MODULE_FILENAME_H_

// Header contents...

#endif  // SOURCERER_MODULE_FILENAME_H_
```

**Examples:**
```cpp
// src/core/binary.h
#ifndef SOURCERER_CORE_BINARY_H_
#define SOURCERER_CORE_BINARY_H_
// ...
#endif  // SOURCERER_CORE_BINARY_H_

// src/cpu/m6502/cpu_6502.h
#ifndef SOURCERER_CPU_M6502_CPU_6502_H_
#define SOURCERER_CPU_M6502_CPU_6502_H_
// ...
#endif  // SOURCERER_CPU_M6502_CPU_6502_H_
```

## Modern C++17 Requirements

### Use Modern Features
- ✅ `auto` for complex types (not when it obscures type)
- ✅ Smart pointers (`std::unique_ptr`, `std::shared_ptr`)
- ✅ `nullptr` (never `NULL` or `0`)
- ✅ `enum class` (never plain `enum`)
- ✅ Range-based for loops
- ✅ `std::optional` for optional return values
- ✅ `[[nodiscard]]` for important return values

```cpp
// GOOD - modern C++17
auto cpu = CpuRegistry::Create("6502");  // auto OK (type is obvious from context)
std::unique_ptr<Formatter> formatter = CreateFormatter();
std::optional<Symbol> symbol = symbol_table.GetSymbol(address);

[[nodiscard]] bool IsValidAddress(uint32_t address) const;

for (const auto& instruction : instructions) {  // Range-based for
  // Process instruction
}

// BAD - old C++ style
CpuPlugin* cpu = CpuRegistry::Create("6502");  // Raw pointer, potential leak
Symbol* symbol = symbol_table.GetSymbol(address);  // Raw pointer, nullptr checking
```

### Const Correctness
- ✅ Mark methods `const` if they don't modify state
- ✅ Use `const` references for parameters
- ✅ Never use `const_cast` without justification

```cpp
// GOOD - const everywhere appropriate
class Binary {
public:
  const std::vector<uint8_t>& data() const { return data_; }
  bool IsValidAddress(uint32_t address) const;

  void ProcessData(const std::vector<uint8_t>& data);
};

// BAD - missing const
class Binary {
public:
  std::vector<uint8_t>& data() { return data_; }  // Exposes mutable reference!
  bool IsValidAddress(uint32_t address);  // Should be const
};
```

### Override Keyword
- ✅ Always use `override` for virtual method overrides
- ✅ Never use `virtual` and `override` together

```cpp
// GOOD
class Cpu6502 : public CpuPlugin {
public:
  core::Instruction Disassemble(...) const override;  // override, no virtual
  std::string Name() const override;
};

// BAD
class Cpu6502 : public CpuPlugin {
public:
  virtual core::Instruction Disassemble(...) const override;  // Redundant virtual
  core::Instruction Disassemble(...) const;  // Missing override (dangerous!)
};
```

## Anti-Patterns (Forbidden)

The following patterns are **strictly forbidden** in Sourcerer code:

### ❌ Tabs in Source Files
Use 2 spaces for indentation. Configure your editor:
```
# .editorconfig
[*.{cpp,h}]
indent_style = space
indent_size = 2
```

### ❌ `using namespace` in Headers
Never pollute the global namespace in headers:
```cpp
// BAD - in header file
using namespace std;  // Pollutes namespace for all includers!

// GOOD - in implementation file (use sparingly)
// code_analyzer.cpp
using namespace std;  // OK in .cpp files (still use sparingly)

// BETTER - explicit qualification
std::vector<uint8_t> data;
std::unique_ptr<CpuPlugin> cpu;
```

### ❌ Raw `new`/`delete` in Application Code
Use smart pointers or containers:
```cpp
// BAD - manual memory management
CpuPlugin* cpu = new Cpu6502();
// ... easy to leak if exception thrown ...
delete cpu;

// GOOD - RAII with smart pointers
std::unique_ptr<CpuPlugin> cpu = std::make_unique<Cpu6502>();
// Automatically cleaned up

// GOOD - containers manage memory
std::vector<uint8_t> data(1024);  // No manual cleanup needed
```

### ❌ Magic Numbers
Use named constants:
```cpp
// BAD - magic numbers
if (size > 100000) { /* ... */ }
if (confidence > 0.6f) { /* ... */ }

// GOOD - named constants
constexpr size_t kMaxInstructions = 100000;
constexpr float kMinConfidence = 0.6f;

if (size > kMaxInstructions) { /* ... */ }
if (confidence > kMinConfidence) { /* ... */ }
```

### ❌ Global Mutable State
Avoid global variables; use dependency injection:
```cpp
// BAD - global mutable state
CpuPlugin* g_current_cpu = nullptr;  // Global variable (error-prone!)

void Analyze() {
  g_current_cpu->Disassemble(...);  // Depends on global state
}

// GOOD - dependency injection
class Analyzer {
public:
  Analyzer(CpuPlugin* cpu) : cpu_(cpu) {}

  void Analyze() {
    cpu_->Disassemble(...);  // Explicit dependency
  }

private:
  CpuPlugin* cpu_;
};
```

### ❌ Deep Nesting (>3 Levels)
Refactor deeply nested code using early returns:
```cpp
// BAD - deep nesting
void Process() {
  if (condition1) {
    if (condition2) {
      if (condition3) {
        if (condition4) {
          // Finally do work (hard to read!)
        }
      }
    }
  }
}

// GOOD - early returns
void Process() {
  if (!condition1) return;
  if (!condition2) return;
  if (!condition3) return;
  if (!condition4) return;

  // Do work (easy to read!)
}
```

## Code Review Checklist

Before submitting code for review, verify:

- ☐ **No tabs** - Only 2-space indentation
- ☐ **Naming conventions** - PascalCase for types, snake_case for variables
- ☐ **Include guards** - Correct format with full path
- ☐ **Const correctness** - Methods marked const appropriately
- ☐ **Smart pointers** - No raw new/delete
- ☐ **Modern C++** - Using C++17 features appropriately
- ☐ **No magic numbers** - Named constants used
- ☐ **Builds without warnings** - Clean compilation with `-Wall -Wextra`
- ☐ **Tests pass** - All unit tests green
- ☐ **Architecture compliance** - See [PROJECT-architecture.md](PROJECT-architecture.md)

## Tool Configuration

### clang-format
Use provided `.clang-format` in project root (2-space, Google style).

### clang-tidy
Run with provided `.clang-tidy` configuration.

### CMake Build
```bash
mkdir build && cd build
cmake .. -DCMAKE_CXX_FLAGS="-Wall -Wextra -Wpedantic"
make -j8
```

---

**These rules work alongside the shared Cortexa standards to maintain consistency across the Sourcerer codebase.**
