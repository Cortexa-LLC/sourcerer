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
│   ├── cpu_state.h         # Abstract CPU state for simulation
│   ├── m6809/              # 6809 implementation
│   │   ├── cpu_6809.cpp    # 6809 disassembler
│   │   └── cpu_state_6809.h # 6809 execution state
│   └── m6502/              # 6502/65C02 implementation
│       ├── cpu_6502.cpp    # 6502 disassembler
│       └── cpu_state_6502.h # 6502 execution state
├── analysis/       # Code flow analysis (CPU-agnostic)
│   ├── code_analyzer.cpp        # Main analyzer
│   └── execution_simulator.cpp  # Dynamic branch analysis
├── output/         # Output formatters
│   └── merlin_formatter.cpp   # Assembly output
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

✅ **Phase 4: Execution Simulation (Dynamic Analysis)**
- Abstract `CpuState` interface for polymorphic CPU state
- CPU-specific state implementations (`CpuState6809`, `CpuState6502`)
- `ExecutionSimulator` now supports all CPU architectures
- Added virtual methods to `CpuPlugin`:
  - `CreateCpuState()` - Creates CPU-specific state
  - New method added to `CpuState`:
    - `ExecuteInstruction()` - Simulates instruction effects
    - `EvaluateBranchCondition()` - Determines if branch is taken
- Dynamic branch analysis discovers conditional code paths
- Integration into analysis pipeline for improved coverage

### Test Results

**ZAXXON.BIN** (CoCo 6809 arcade game, 16,646 bytes):
- ✅ **100% of reachable code discovered**
- ✅ Execution simulation working for both 6809 and 6502
- ✅ All 60 analysis tests passing
- ✅ All 52 6502 tests passing
- ✅ Dynamic branch discovery operational

## Current Status: Ready for Production

The disassembler now features complete multi-CPU support with dynamic analysis capabilities.

### Execution Simulation Architecture

The `ExecutionSimulator` provides dynamic branch analysis to discover conditional code paths:

#### CPU State Abstraction

```cpp
// Abstract CPU state interface
class CpuState {
 public:
  virtual ~CpuState() = default;
  virtual void Reset() = 0;
  virtual uint32_t GetPC() const = 0;
  virtual void SetPC(uint32_t pc) = 0;

  // CPU-specific instruction simulation
  virtual bool ExecuteInstruction(
      const core::Instruction& inst,
      std::function<uint8_t(uint32_t)> read_memory,
      std::function<void(uint32_t, uint8_t)> write_memory) = 0;

  // CPU-specific branch evaluation
  virtual bool EvaluateBranchCondition(const std::string& mnemonic) = 0;
};
```

#### Integration with CpuPlugin

```cpp
class CpuPlugin {
 public:
  // ... existing methods ...

  // NEW: Create CPU-specific state for simulation
  virtual std::unique_ptr<CpuState> CreateCpuState() const = 0;
};
```

#### How It Works

1. **Initialization**: ExecutionSimulator creates CPU-specific state via `cpu->CreateCpuState()`
2. **Simulation Loop**: For each instruction:
   - Disassemble current PC
   - Execute instruction (updates CPU state)
   - Evaluate branches to determine taken/not-taken
   - Discover new entry points from branch targets
3. **Integration**: Called during analysis passes to enhance code discovery

**Example Usage:**
```cpp
ExecutionSimulator sim(cpu_plugin, binary);
std::set<uint32_t> discovered = sim.SimulateFrom(entry_point, 100);
// Returns addresses discovered through branch analysis
```

## File Locations

### Core Analysis Files

- `src/analysis/code_analyzer.h` - Main analysis orchestrator
- `src/analysis/code_analyzer.cpp` - Coordinates all analysis strategies
- `src/analysis/execution_simulator.h` - Dynamic analysis interface
- `src/analysis/execution_simulator.cpp` - Execution simulation implementation

### CPU Plugin Files

- `src/cpu/cpu_plugin.h` - Abstract CPU plugin interface
- `src/cpu/cpu_state.h` - Abstract CPU state interface
- `src/cpu/m6809/cpu_6809.h` - 6809 CPU plugin
- `src/cpu/m6809/cpu_state_6809.h` - 6809 state implementation
- `src/cpu/m6502/cpu_6502.h` - 6502 CPU plugin
- `src/cpu/m6502/cpu_state_6502.h` - 6502 state implementation

### Test Files

- `tests/test_execution_simulator_enhanced.cpp` - ExecutionSimulator tests
- `test_coco.sh` - Integration test with ZAXXON.BIN
- `test_output/zaxxon.asm` - Output verification

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

### Issue: Execution simulation stops after one instruction
**Solution:** Check CPU state implementation - ensure `ExecuteInstruction()` returns true for most instructions, false only for RTS/RTI

### Issue: Branch conditions not evaluated correctly
**Solution:** Verify CPU state flag updates in `ExecuteInstruction()` and condition checks in `EvaluateBranchCondition()`

### Issue: Wrong endianness in memory reads
**Solution:** Check CPU variant and handle big-endian (6809) vs little-endian (6502) in `ReadByte()`/`ReadWord()`

### Issue: Operand validation failures during disassembly
**Solution:** Ensure immediate mode operands don't incorrectly check next byte (which may be next instruction's opcode)

## Next Steps

- **Phase 5**: Jump table detection (dispatch tables, indexed jump arrays)
- **Phase 6**: Advanced features (stack frame analysis, data type inference)
- **Phase 7**: Clean code refactoring (strategy pattern extraction)
- **Test**: More CoCo and Apple II binaries
- **New CPUs**: Z80, 65816, 68000

## References

- `.clinerules/rules.md` - Coding standards
- `README.md` - User documentation
- `docs/ARCHITECTURE.md` - Detailed architecture documentation
- `docs/EXECUTION_SIMULATOR_REFACTOR.md` - Execution simulator design
- Phase 3 implementation: Entry point discovery in `code_analyzer.cpp`
- Phase 4 implementation: Execution simulation in `execution_simulator.cpp`
- CPU state abstraction: `cpu_state.h`, `cpu_state_6809.h`, `cpu_state_6502.h`
- SOLID refactoring: CPU plugins with analysis capabilities
