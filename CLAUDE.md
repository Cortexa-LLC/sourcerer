# Sourcerer - Claude Code Bootstrap

**Project:** Sourcerer - Multi-CPU Disassembler for Vintage Computer Binaries
**Repository:** git@github.com:Cortexa-LLC/sourcerer.git
**Framework Version:** ai-pack 1.0.0 (Foundation)

---

## ⚠️ CRITICAL: Task Packet Requirement

**BEFORE starting ANY non-trivial task, you MUST:**

1. **Create task packet directory:** `.ai/tasks/YYYY-MM-DD_task-name/`
2. **Copy ALL 5 templates** from `.ai-pack/templates/task-packet/`
3. **Fill out 00-contract.md** with requirements and acceptance criteria
4. **Fill out 10-plan.md** with implementation approach
5. **Update 20-work-log.md** during implementation
6. **ONLY THEN** begin implementation

**Non-Trivial = Any task that:**
- Requires >2 steps
- Involves code changes (writing tests, modifying C++ code)
- Takes >30 minutes
- Needs verification (tests, coverage, build)

**This is MANDATORY. Do not skip this step.**

**Example:**
```bash
# For coverage improvement task:
TASK_ID=$(date +%Y-%m-%d)_coverage-improvement
mkdir -p .ai/tasks/$TASK_ID
cp .ai-pack/templates/task-packet/*.md .ai/tasks/$TASK_ID/
# Then fill out 00-contract.md and 10-plan.md BEFORE starting work
```

---

## Project Overview

**Sourcerer** is a modern, multi-CPU disassembler for vintage computer binaries. It supports:
- **CPU Architectures**: Motorola 6809, MOS 6502, WDC 65C02
- **Disk Formats**: CoCo DSK, Apple II DSK, Commodore D64
- **Output Formats**: Assembly source code (reassembleable)

**Key Feature**: Smart code flow analysis that distinguishes code from data blocks using recursive traversal, heuristics, and CPU-specific pattern matching.

---

## Framework Integration

This project uses the **ai-pack framework** for structured AI-assisted development.

### Directory Structure

```
sourcerer/
├── .ai-pack/           # Git submodule (read-only shared framework)
│   ├── gates/          # Quality gates (safety, persistence, verification)
│   ├── quality/        # Clean code standards
│   ├── roles/          # Agent role definitions
│   ├── workflows/      # Task workflow templates
│   └── templates/      # Task packet templates
├── .ai/                # Local workspace (project-specific, mutable)
│   ├── tasks/          # Active task packets (YYYY-MM-DD_task-name/)
│   └── repo-overrides.md  # Optional project-specific rules
├── CLAUDE.md           # This file
└── src/                # Source code (see Architecture below)
```

**Key Invariants:**
- ✅ Task packets belong in `.ai/tasks/` (local, mutable)
- ❌ NEVER put task state in `.ai-pack/` (shared, read-only)
- ✅ Framework improvements go to ai-pack repo, not ad-hoc edits

---

## Required Reading: Gates and Standards

Before any non-trivial task, read these foundational documents:

### Quality Gates (Must Follow)
1. **[.ai-pack/gates/00-global-gates.md](.ai-pack/gates/00-global-gates.md)** - Universal rules (safety, quality, communication)
2. **[.ai-pack/gates/10-persistence.md](.ai-pack/gates/10-persistence.md)** - File operations and state management
3. **[.ai-pack/gates/20-tool-policy.md](.ai-pack/gates/20-tool-policy.md)** - Tool usage policies
4. **[.ai-pack/gates/30-verification.md](.ai-pack/gates/30-verification.md)** - Verification requirements

### Engineering Standards
- **[.ai-pack/quality/engineering-standards.md](.ai-pack/quality/engineering-standards.md)** - Clean code standards index
- **[.ai-pack/quality/clean-code/](.ai-pack/quality/clean-code/)** - Detailed standards by topic

---

## Sourcerer Architecture

### Source Code Structure

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

---

## Technology Stack

**Language:** C++17
**Build System:** CMake 3.15+
**Compiler:** Clang (Xcode) / GCC
**Test Framework:** Google Test
**Coverage Target:** 80-90%

**Build Commands:**
```bash
# Configure
cmake -B build -DCMAKE_BUILD_TYPE=Debug

# Build
cmake --build build

# Test
ctest --test-dir build --output-on-failure

# Coverage (with instrumentation)
cmake -B build_coverage -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS="--coverage"
cmake --build build_coverage
./build_coverage/tests/test_analysis
gcov build_coverage/src/analysis/CMakeFiles/analysis.dir/code_analyzer.cpp.gcno
```

**Integration Tests:**
```bash
# Run all tests (includes round-trip validation)
ctest --test-dir build --output-on-failure

# Run only integration tests
ctest --test-dir build -L integration --output-on-failure

# Round-trip validation (Binary → Disassemble → Reassemble → Binary)
# Tests ZAXXON (6809), GRAFIX (6502), GAMEBG (6502)
python3 tests/test_roundtrip.py

# Individual binary tests
python3 tests/test_roundtrip.py --test zaxxon
python3 tests/test_roundtrip.py --test grafix
python3 tests/test_roundtrip.py --test gamebg
```

---

## Current Development Status

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

**Unit Tests:**
- ✅ **690 tests passing** (100% pass rate)
- ✅ All CPU plugins: 6809, 6502, 65C02
- ✅ All formatters: EDTASM, Merlin, SCMasm
- ✅ Analysis engines: Code flow, execution simulation, misalignment resolution
- ✅ Code coverage: 45.11% (target: 80-90%)

**Round-Trip Validation** (Binary → Disassemble → Reassemble → Binary):
- ✅ **ZAXXON.BIN** (6809, 16,651 bytes): PERFECT MATCH (MD5: 1ed87a23f2dfdc6930e694a7d9eb0f61)
- ✅ **GRAFIX.bin** (6502, 2,567 bytes): PERFECT MATCH (MD5: 9ac875b492d8553abc30578a3fa57240)
- ✅ **GAMEBG.bin** (6502, 1,570 bytes): PERFECT MATCH (MD5: 0482666488dc2715530d0bf7a6e86fdb)
- ✅ 100% reassembleable output using vasm6809_edtasm and vasm6502_merlin

**Analysis Performance:**
- ✅ **100% of reachable code discovered** in ZAXXON.BIN
- ✅ Execution simulation working for both 6809 and 6502
- ✅ Dynamic branch discovery operational
- ✅ Misalignment resolution: 98.5% accuracy on 20+ binaries

**Current Status:** Production-ready for core features. Code coverage improvement in progress.

---

## Task Management Protocol

### MANDATORY: Task Packet Creation

**CRITICAL REQUIREMENT:** Every non-trivial task MUST have a task packet in `.ai/tasks/` created BEFORE implementation begins.

**1. Create Task Packet**

```bash
# Create task directory
TASK_ID=$(date +%Y-%m-%d)_task-name
mkdir -p .ai/tasks/$TASK_ID

# Copy templates from .ai-pack
cp .ai-pack/templates/task-packet/00-contract.md .ai/tasks/$TASK_ID/
cp .ai-pack/templates/task-packet/10-plan.md .ai/tasks/$TASK_ID/
cp .ai-pack/templates/task-packet/20-work-log.md .ai/tasks/$TASK_ID/
cp .ai-pack/templates/task-packet/30-review.md .ai/tasks/$TASK_ID/
cp .ai-pack/templates/task-packet/40-acceptance.md .ai/tasks/$TASK_ID/
```

**2. Follow Task Lifecycle**

All task packets go through these phases:

1. **Contract** (`00-contract.md`) - Define requirements and acceptance criteria
2. **Plan** (`10-plan.md`) - Document implementation approach
3. **Work Log** (`20-work-log.md`) - Track execution progress
4. **Review** (`30-review.md`) - Quality assurance
5. **Acceptance** (`40-acceptance.md`) - Sign-off and completion

**3. CRITICAL: Task Packet Location**

✅ **Correct:** `.ai/tasks/YYYY-MM-DD_task-name/`
❌ **NEVER:** `.ai-pack/` (this is shared framework, not for task state)

---

## Role Enforcement

Choose your role based on the task:

### Orchestrator Role
**Use when:** Complex multi-step tasks requiring coordination

**Responsibilities:**
- Break down work into subtasks
- Delegate to worker agents
- Monitor progress
- Coordinate reviews

**Reference:** [.ai-pack/roles/orchestrator.md](.ai-pack/roles/orchestrator.md)

---

### Worker Role
**Use when:** Implementing specific, well-defined tasks

**Responsibilities:**
- Write code and tests
- Follow established patterns
- Update work log
- Report progress and blockers

**Reference:** [.ai-pack/roles/worker.md](.ai-pack/roles/worker.md)

---

### Reviewer Role
**Use when:** Conducting quality assurance

**Responsibilities:**
- Review code against standards
- Verify test coverage
- Check architecture consistency
- Document findings

**Reference:** [.ai-pack/roles/reviewer.md](.ai-pack/roles/reviewer.md)

---

## Workflow Selection

Choose appropriate workflow for the task type:

| Task Type | Workflow | When to Use |
|-----------|----------|-------------|
| General | [standard.md](.ai-pack/workflows/standard.md) | Any task not fitting specialized workflows |
| New Feature | [feature.md](.ai-pack/workflows/feature.md) | Adding new functionality |
| Bug Fix | [bugfix.md](.ai-pack/workflows/bugfix.md) | Fixing defects |
| Refactoring | [refactor.md](.ai-pack/workflows/refactor.md) | Improving code structure |
| Investigation | [research.md](.ai-pack/workflows/research.md) | Understanding code/architecture |

---

## Execution Simulation Architecture

The `ExecutionSimulator` provides dynamic branch analysis to discover conditional code paths:

### CPU State Abstraction

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

### Integration with CpuPlugin

```cpp
class CpuPlugin {
 public:
  // ... existing methods ...

  // NEW: Create CPU-specific state for simulation
  virtual std::unique_ptr<CpuState> CreateCpuState() const = 0;
};
```

### How It Works

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

---

## Critical File Locations

### Analysis Core
- `src/analysis/code_analyzer.h` - Main analysis orchestrator
- `src/analysis/code_analyzer.cpp` - Coordinates all analysis strategies
- `src/analysis/execution_simulator.h` - Dynamic analysis interface
- `src/analysis/execution_simulator.cpp` - Execution simulation implementation

### CPU Plugins
- `src/cpu/cpu_plugin.h` - Abstract CPU plugin interface
- `src/cpu/cpu_state.h` - Abstract CPU state interface
- `src/cpu/cpu_registry.h` - CPU plugin factory
- `src/cpu/m6809/cpu_6809.h` - 6809 CPU plugin
- `src/cpu/m6809/cpu_state_6809.h` - 6809 state implementation
- `src/cpu/m6502/cpu_6502.h` - 6502 CPU plugin
- `src/cpu/m6502/cpu_state_6502.h` - 6502 state implementation

### Tests
- `tests/test_code_analyzer_integration.cpp` - CodeAnalyzer integration tests
- `tests/test_execution_simulator_enhanced.cpp` - ExecutionSimulator tests
- `test_coco.sh` - Integration test with ZAXXON.BIN
- `test_output/zaxxon.asm` - Output verification

---

## Common Issues and Solutions

### Issue: Execution simulation stops after one instruction
**Solution:** Check CPU state implementation - ensure `ExecuteInstruction()` returns true for most instructions, false only for RTS/RTI

### Issue: Branch conditions not evaluated correctly
**Solution:** Verify CPU state flag updates in `ExecuteInstruction()` and condition checks in `EvaluateBranchCondition()`

### Issue: Wrong endianness in memory reads
**Solution:** Check CPU variant and handle big-endian (6809) vs little-endian (6502) in `ReadByte()`/`ReadWord()`

### Issue: Operand validation failures during disassembly
**Solution:** Ensure immediate mode operands don't incorrectly check next byte (which may be next instruction's opcode)

### Issue: Jump tables detected in CODE regions
**Solution:** Only scan DATA/UNKNOWN regions for jump table candidates

### Issue: Tests hanging indefinitely
**Solution:** Check for dangling pointers - ensure CPU plugin lifetime exceeds analyzer lifetime

---

## Common Operations

### Starting a New Task

1. Read gates and standards (see Required Reading above)
2. Create task packet in `.ai/tasks/`
3. Fill out `00-contract.md` with requirements
4. Select appropriate workflow
5. Assume appropriate role
6. Execute workflow phases

### Working on Existing Task

1. Read task packet in `.ai/tasks/YYYY-MM-DD_task-name/`
2. Review current phase
3. Continue from where left off
4. Update work log regularly

### Updating Framework

```bash
# Update shared framework (preserves .ai/tasks/)
git submodule update --remote .ai-pack
git add .ai-pack
git commit -m "Update ai-pack framework"
```

### Running Tests with Coverage

```bash
# Build with coverage instrumentation
cmake -B build_coverage -DCMAKE_CXX_FLAGS="--coverage"
cmake --build build_coverage

# Run tests
./build_coverage/tests/test_analysis

# Generate coverage report
gcov build_coverage/src/analysis/CMakeFiles/analysis.dir/code_analyzer.cpp.gcno
```

---

## Invariants (Critical)

### ✅ DO
- Create task packets in `.ai/tasks/` for non-trivial work
- Follow gates and workflows
- Update work logs regularly
- Reference standards when making decisions
- Run tests before committing
- Use CMake build system (not standalone g++)
- Maintain CPU-agnostic design in CodeAnalyzer
- Keep CPU-specific logic in CPU plugins

### ❌ NEVER
- Put task packets in `.ai-pack/`
- Edit `.ai-pack/` files directly (contribute to ai-pack repo instead)
- Overwrite `.ai/tasks/` during updates
- Skip gate checkpoints
- Proceed with failing tests
- Use magic strings for CPU variants (use CpuVariant enum)
- Add CPU-specific code to CodeAnalyzer
- Use `git rebase -i` or `git add -i` (not supported in automation)

---

## Next Steps

### Immediate Priorities
- **Code Coverage Improvement**: Current 45.11%, target 80-90%
  - Phase 1: ✅ CodeAnalyzer integration tests (complete)
  - Phase 2: EdtasmFormatter tests
  - Phase 3: CPU plugin edge cases
  - Phase 4-7: Data detection, reclassification, integration workflows

### Future Phases
- **Phase 5**: Jump table detection (dispatch tables, indexed jump arrays)
- **Phase 6**: Advanced features (stack frame analysis, data type inference)
- **Phase 7**: Clean code refactoring (strategy pattern extraction)
- **Testing**: More CoCo and Apple II binaries
- **New CPUs**: Z80, 65816, 68000

---

## Quick Reference

**Framework:**
- Gates: `.ai-pack/gates/`
- Roles: `.ai-pack/roles/`
- Workflows: `.ai-pack/workflows/`
- Templates: `.ai-pack/templates/`
- Standards: `.ai-pack/quality/`

**Project:**
- Task Packets: `.ai/tasks/YYYY-MM-DD_task-name/`
- Overrides: `.ai/repo-overrides.md` (optional)
- Source: `src/`
- Tests: `tests/`
- Build: `build/` (or `build_coverage/`)

---

## Getting Help

- **Framework Documentation:** See `.ai-pack/README.md`
- **Standards Index:** See `.ai-pack/quality/engineering-standards.md`
- **Workflow Guides:** See `.ai-pack/workflows/*.md`
- **Role Definitions:** See `.ai-pack/roles/*.md`
- **Architecture Details:** See `docs/ARCHITECTURE.md`
- **Execution Simulator:** See `docs/EXECUTION_SIMULATOR_REFACTOR.md`

---

**Last Updated:** 2026-01-07
**Framework Version:** ai-pack 1.0.0 (Foundation)
**Project Status:** Production-ready, coverage improvement in progress
