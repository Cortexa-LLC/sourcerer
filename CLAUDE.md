# Sourcerer - Claude Context

This document provides context for Claude Code sessions working on the Sourcerer disassembler project.

## Project Overview

**Sourcerer** is a modern, multi-CPU disassembler for vintage computer binaries. It supports:
- **CPU Architectures**: Motorola 6809, MOS 6502, WDC 65C02
- **Disk Formats**: CoCo DSK, Apple II DSK, Commodore D64
- **Output Formats**: Assembly source code (reassembleable)

**Key Feature**: Smart code flow analysis that distinguishes code from data blocks using recursive traversal, heuristics, and CPU-specific pattern matching.

## Architecture

```
src/
├── core/           # Data structures, types (CPU-agnostic)
│   ├── instruction.h       # Instruction representation
│   ├── address_map.h       # Code/data tracking
│   └── binary.h            # Binary file representation
├── cpu/            # CPU plugins (SOLID architecture)
│   ├── cpu_plugin.h        # Abstract interface
│   ├── m6809/              # 6809 implementation
│   └── m6502/              # 6502/65C02 implementation
├── analysis/       # Code flow analysis (CPU-agnostic)
│   └── code_analyzer.cpp   # Main analyzer
├── formats/        # Output formatters
│   └── asm_formatter.cpp   # Assembly output
└── disk/           # Disk extractors
    └── coco_extractor.cpp  # CoCo DSK support
```

### Key Design Patterns

**Plugin Architecture (SOLID):**
- `CodeAnalyzer` depends on `CpuPlugin` interface (not concrete CPUs)
- CPU-specific logic lives in CPU plugins only
- Easy to add new architectures without modifying analyzer

**Dependency Injection:**
```cpp
// Dependencies injected via constructor
CodeAnalyzer analyzer(cpu_plugin, binary);
```

**Separation of Concerns:**
- `CodeAnalyzer`: Code flow analysis (CPU-agnostic)
- `Cpu6809/Cpu6502`: CPU-specific disassembly and analysis
- `AsmFormatter`: Output generation

## Current Status

### Completed Phases

✅ **Phase 1: Recursive Traversal Engine**
- Replaced queue-based BFS with recursive DFS
- Explores both taken/not-taken branches exhaustively
- Multi-pass analysis until convergence

✅ **Phase 2: Conservative Reclassification**
- Smarter second pass to avoid destroying valid code
- Requires 2+ heuristics before reclassifying CODE as DATA
- Protects cross-referenced regions

✅ **Phase 3: Entry Point Discovery**
- Scans interrupt vectors (CPU-specific)
- Pattern-matches subroutine prologues (PSHS for 6809, PHP/PHA for 6502)
- Discovers unreachable code regions

✅ **SOLID Architecture Refactoring**
- Moved CPU-specific analysis into CPU plugins
- `CodeAnalyzer` is now fully CPU-agnostic
- Added 5 virtual methods to `CpuPlugin`:
  - `GetAnalysisCapabilities()`
  - `GetInterruptVectors()`
  - `ReadVectorTarget()`
  - `LooksLikeSubroutineStart()`
  - `IsLikelyCode()`

### Test Results

**ZAXXON.BIN** (CoCo 6809 arcade game, 16,646 bytes):
- ✅ **98.6% coverage** (16,420 bytes disassembled)
- ✅ 4,461 instructions
- ✅ 3,375 entry points discovered
- ❌ 226 bytes remaining (likely jump tables or unreachable code)

## Current Task: Phase 4 - Jump Table Detection

### Goal
Discover remaining 226 bytes by detecting jump tables (dispatch tables, indexed jump arrays).

### Why Jump Tables?
Arcade games and complex software use jump tables for:
- Level handlers (indexed by level number)
- Enemy AI routines (indexed by enemy type)
- Sprite rendering (indexed by sprite ID)
- Event handlers (indexed by event type)

### Implementation Spec

#### Data Structures

```cpp
// In code_analyzer.h
struct JumpTableCandidate {
  uint32_t start_address;        // First entry
  uint32_t end_address;          // Last entry
  std::vector<uint32_t> targets; // Target addresses
  float confidence;              // 0.0-1.0 score

  size_t GetEntryCount() const { return targets.size(); }
  size_t GetTableSize() const { return end_address - start_address + 1; }
};
```

#### Configuration Constants

```cpp
static constexpr size_t MIN_JUMP_TABLE_ENTRIES = 3;    // Minimum entries
static constexpr size_t MAX_JUMP_TABLE_ENTRIES = 256;  // Maximum entries
static constexpr float MIN_CONFIDENCE = 0.6f;          // Minimum confidence
```

#### Algorithm

**1. Find Candidates (`FindJumpTableCandidates`)**

Scan DATA/UNKNOWN regions for consecutive 16-bit addresses:

```cpp
for each address in [DATA, UNKNOWN] regions:
  vector<uint32_t> targets

  while (has 2 more bytes):
    uint16_t value = ReadAddress(current, cpu)  // Handles endianness

    if (IsLikelyCodePointer(value)):
      targets.push_back(value)
      current += 2
    else:
      break

  if (targets.size() >= MIN_JUMP_TABLE_ENTRIES):
    candidate = JumpTableCandidate{start, current-1, targets, 0.0}
    candidate.confidence = CalculateTableConfidence(candidate)
    if (candidate.confidence >= MIN_CONFIDENCE):
      candidates.push_back(candidate)
```

**2. Confidence Scoring (`CalculateTableConfidence`)**

Score based on multiple factors:
- **Entry count**: +0.2 per entry (max +0.4 at 5+ entries)
- **Address proximity**: +0.2 if all addresses within 4KB
- **Code validation**: +0.3 if >80% pass `IsLikelyCode()`
- **Alignment**: +0.1 if all addresses are even (6809) or aligned (6502)
- **No overlap**: +0.1 if targets don't overlap existing DATA
- **Cross-references**: +0.1 if table has incoming xrefs from CODE

Target: 0.6 minimum confidence

**3. Validation (`ValidateJumpTable`)**

Check:
- ✅ Confidence >= MIN_CONFIDENCE
- ✅ Entry count in valid range
- ✅ All targets within binary bounds
- ✅ At least 50% of targets validate as likely code
- ✅ No targets point to middle of known instructions

**4. Processing (`ProcessJumpTable`)**

For valid tables:
1. Mark table region as DATA
2. Add each target as discovered entry point
3. Add cross-references from table to targets
4. Log discovery

```cpp
void CodeAnalyzer::ProcessJumpTable(const JumpTableCandidate& table,
                                    core::AddressMap* address_map) {
  // Mark table as DATA
  for (uint32_t addr = table.start_address; addr <= table.end_address; ++addr) {
    address_map->SetType(addr, core::AddressType::DATA);
  }

  // Add targets as entry points
  for (uint32_t target : table.targets) {
    if (IsValidAddress(target)) {
      discovered_entry_points_.insert(target);
      address_map->AddXref(target, table.start_address);
    }
  }

  LOG_INFO("Jump table at $" + std::to_string(table.start_address) +
           ": " + std::to_string(table.GetEntryCount()) + " entries");
}
```

**5. Integration Point**

Add to `RecursiveAnalyze()` after each pass:

```cpp
void CodeAnalyzer::RecursiveAnalyze(core::AddressMap* address_map) {
  for (int pass = 0; pass < MAX_PASSES; ++pass) {
    int bytes_discovered = RunAnalysisPass(address_map);

    if (bytes_discovered == 0) break;

    if (pass < MAX_PASSES - 1) {
      DiscoverEntryPoints(address_map);
      ScanForJumpTables(address_map);  // ← Add here
    }
  }
}
```

#### Implementation Order

1. ✅ Add `JumpTableCandidate` struct to header
2. ⏳ Implement `IsLikelyCodePointer()` - Simple address validation
3. ⏳ Implement `FindJumpTableCandidates()` - Scan for tables
4. ⏳ Implement `CalculateTableConfidence()` - Score candidates
5. ⏳ Implement `ValidateJumpTable()` - Validate candidates
6. ⏳ Implement `ProcessJumpTable()` - Add entry points
7. ⏳ Complete `ScanForJumpTables()` - Main entry point
8. ⏳ Integrate into `RecursiveAnalyze()`
9. ⏳ Build and test with ZAXXON.BIN
10. ⏳ Tune confidence thresholds if needed

### Success Criteria

- ✅ No false positives on existing working binaries
- ✅ ZAXXON.BIN coverage: 99%+ (or justify remaining bytes)
- ✅ CPU-agnostic implementation (works for both 6809 and 6502)
- ✅ Builds without warnings
- ✅ All tests pass

### Important Implementation Notes

**CPU Agnostic:**
- Use `cpu->IsLikelyCode()` to validate targets
- Use `cpu->MaxAddress()` for bounds checking
- Handle endianness via CPU plugin or binary helpers
- No hard-coded CPU checks in CodeAnalyzer

**Conservative Detection:**
- Prefer false negatives over false positives
- Require strong confidence (0.6+)
- Validate targets thoroughly
- Log all discoveries for debugging

**Endianness Handling:**
```cpp
// Read 16-bit address considering CPU endianness
uint16_t ReadAddress(const uint8_t* data, cpu::CpuPlugin* cpu) {
  if (cpu->GetVariant() == cpu::CpuVariant::MOTOROLA_6809) {
    // Big-endian
    return (data[0] << 8) | data[1];
  } else {
    // Little-endian (6502)
    return data[0] | (data[1] << 8);
  }
}
```

## File Locations

### Key Files to Modify

- `src/analysis/code_analyzer.h` - Add jump table data structures and methods
- `src/analysis/code_analyzer.cpp` - Implement jump table detection

### Test Files

- `test_coco.sh` - Integration test with ZAXXON.BIN
- `test_output/zaxxon.asm` - Output to verify

## Building and Testing

```bash
# Build
cmake --build build

# Run CoCo test (ZAXXON.BIN)
./test_coco.sh

# Check statistics
./test_coco.sh | grep -E "(discovered|Code:|Data:)"
```

## Common Issues and Solutions

### Issue: Jump tables detected in CODE regions
**Solution:** Only scan DATA/UNKNOWN regions

### Issue: False positives
**Solution:** Increase MIN_CONFIDENCE threshold or improve scoring

### Issue: Missing tables
**Solution:** Decrease MIN_CONFIDENCE or improve scoring heuristics

### Issue: Wrong endianness
**Solution:** Check CPU variant and handle big-endian (6809) vs little-endian (6502)

## Next Steps After Phase 4

- **Phase 5**: Dynamic analysis (execution simulation) if needed
- **Phase 6**: Advanced features (label generation, comments, data type inference)
- **Test**: More CoCo and Apple II binaries
- **New CPUs**: Z80, 65816, others

## References

- `.clinerules/rules.md` - Coding standards
- `README.md` - User documentation
- Phase 3 implementation in `code_analyzer.cpp` lines 910-1114
- SOLID refactoring in CPU plugins (lines 218-328 in cpu_6809.cpp, cpu_6502.cpp)
