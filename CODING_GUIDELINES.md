# Sourcerer C++ Coding Guidelines

## Overview
This project follows the [C++ Core Guidelines](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines).

## Adopted Standards

### Language Version
- **C++17** (minimum)
- **C++20** preferred when available (for `std::span`)

### Key Principles

#### F.20: For "out" output values, prefer return values to output parameters
```cpp
// ❌ Old style (out-parameters)
void GetSymbol(uint32_t addr, std::string* name, bool* found);

// ✅ Core Guidelines (return std::optional)
std::optional<std::string> GetSymbol(uint32_t addr);
```

#### F.21: To return multiple "out" values, prefer returning a struct
```cpp
// ❌ Old style (multiple out-parameters)
std::string FormatOperand(..., uint32_t* target, size_t* bytes, bool* success);

// ✅ Core Guidelines (return struct)
struct OperandResult {
  std::string operand;
  uint32_t target_address;
  size_t extra_bytes;
  bool success;
};
OperandResult FormatOperand(...);
```

#### I.13: Do not pass an array as a single pointer
```cpp
// ⚠️ Acceptable for now (binary data, plugin interfaces)
core::Instruction Disassemble(const uint8_t* data, size_t size, uint32_t addr);

// ✅ Preferred (when C++20 available)
core::Instruction Disassemble(std::span<const uint8_t> data, uint32_t addr);
```

#### ES.46: Avoid lossy (narrowing, truncating) arithmetic conversions
```cpp
// ❌ Implicit narrowing
uint8_t byte = value;  // if value is int

// ✅ Explicit conversion with check
uint8_t byte = gsl::narrow_cast<uint8_t>(value);  // or static_cast with assertion
```

#### C.45: Don't define a default constructor that only initializes data members
```cpp
// ❌ Unnecessary default constructor
struct Instruction {
  uint32_t address;
  Instruction() : address(0) {}  // Don't do this
};

// ✅ Use in-class member initializers
struct Instruction {
  uint32_t address = 0;
};
```

#### R.1: Manage resources automatically using RAII
```cpp
// ✅ Already doing this
std::unique_ptr<CpuPlugin> Create6809Plugin();
std::vector<uint8_t> bytes;  // automatic cleanup
```

### Intentional Deviations

#### Plugin Interfaces: Stable C++ patterns
**Reason**: External plugins, backwards compatibility, performance-critical binary data

```cpp
// ✅ Acceptable for plugin interfaces
virtual core::Instruction Disassemble(const uint8_t* data, size_t size,
                                     uint32_t address) const = 0;
```

**When we deviate**: Document with `// GUIDELINE DEVIATION:` comment

```cpp
// GUIDELINE DEVIATION (I.13): Binary data interface for plugins
// Will migrate to std::span in C++20
const uint8_t* GetPointer(uint32_t address) const;
```

## Migration Plan

### Phase 1: Immediate (Current Sprint)
- [x] Return structs for multiple outputs (OperandResult pattern)
- [ ] Use `std::optional` for optional returns (symbol table, address map)
- [ ] Document remaining deviations
- [ ] Remove unnecessary default constructors

### Phase 2: Short Term (Next Sprint)
- [ ] Refactor internal APIs to return structs/optionals
- [ ] Add const-correctness throughout
- [ ] Use structured bindings for multi-value returns
- [ ] Apply `[[nodiscard]]` to result types

### Phase 3: Long Term (C++20 Migration)
- [ ] Replace pointer+size with `std::span`
- [ ] Use `std::span` in plugin interfaces (breaking change)
- [ ] Consider `gsl::not_null` for non-nullable pointers
- [ ] Use concepts for CPU plugin requirements

## Code Review Checklist

- [ ] No raw pointers for ownership
- [ ] Multiple return values use struct or tuple
- [ ] Optional values use `std::optional`
- [ ] No naked `new`/`delete`
- [ ] Const-correct
- [ ] `[[nodiscard]]` on result types
- [ ] RAII for all resources

## Tools

### Static Analysis
- **clang-tidy**: Enable Core Guidelines checks
- **cppcheck**: Supplementary checks

### Configuration
See `.clang-tidy` for enabled Core Guidelines checks.
