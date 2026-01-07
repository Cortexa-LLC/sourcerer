# Code Coverage Improvement Plan

## Executive Summary

**Current Coverage**: 40.38%
**Target Coverage**: 80-90%
**Gap**: +40-50 percentage points
**Strategy**: Focus on high-impact components first

This plan prioritizes testing the most critical, under-tested components to efficiently reach the 80-90% clean code target.

---

## Current State Analysis

### Coverage by Category

| Category | Current | Target | Priority |
|----------|---------|--------|----------|
| **Core** (Binary, Instruction, AddressMap) | 89% | ✅ 80-90% | Low |
| **Analysis Helpers** (XrefBuilder, LabelGenerator) | 87% | ✅ 80-90% | Low |
| **Output Utilities** (DataCollector, LabelResolver) | 85% | ✅ 80-90% | Low |
| **Main Analysis** (CodeAnalyzer) | 23% | ❌ 80-90% | **CRITICAL** |
| **CPU Plugins** (6809, 6502) | 35% | ❌ 80-90% | **HIGH** |
| **Formatters** (Edtasm, Merlin, Scmasm) | 46% | ❌ 80-90% | **HIGH** |
| **Execution Sim** | 65% | ⚠️ 80-90% | **MEDIUM** |
| **Other Analysis** (EquateGenerator) | 0% | ❌ 80-90% | **MEDIUM** |

### Impact Analysis

**Highest Impact** (Priority 1):
- CodeAnalyzer: 1,520 lines, 23% → 85% = **+942 lines** (+18% overall)
- EdtasmFormatter: 533 lines, 0% → 85% = **+453 lines** (+8.6% overall)

**High Impact** (Priority 2):
- CPU 6809: 295 lines, 22% → 85% = **+186 lines** (+3.5% overall)
- CPU State 6809: 285 lines, 22% → 85% = **+180 lines** (+3.4% overall)
- MerlinFormatter: 483 lines, 68% → 85% = **+82 lines** (+1.6% overall)

**Medium Impact** (Priority 3):
- Indexed Mode 6809: 150 lines, 0% → 85% = **+128 lines** (+2.4% overall)
- EquateGenerator: 95 lines, 0% → 85% = **+81 lines** (+1.5% overall)
- ExecutionSimulator: 98 lines, 65% → 85% = **+20 lines** (+0.4% overall)

**Projected Coverage After All Phases**: ~85% ✅

---

## Implementation Phases

### Phase 1: CodeAnalyzer Integration Tests (CRITICAL)

**Goal**: Increase CodeAnalyzer coverage from 23% → 85%
**Impact**: +18% overall coverage (40% → 58%)
**Effort**: 15-20 hours

#### Test File
**Create**: `tests/test_code_analyzer_integration.cpp`

#### Test Categories

##### 1.1 Entry Point Discovery (4-5 hours)
Test the entry point discovery subsystem:

```cpp
TEST_F(CodeAnalyzerTest, DiscoverEntryPoints_InterruptVectors) {
  // Test: 6809 SWI3, SWI2, FIRQ, IRQ, SWI, NMI, RESET vectors
  // Expected: 7 entry points discovered from $FFF0-$FFFE
}

TEST_F(CodeAnalyzerTest, DiscoverEntryPoints_SubroutinePrologues_6809) {
  // Test: Scan for PSHS patterns
  // Expected: Subroutines at addresses with PSHS discovered
}

TEST_F(CodeAnalyzerTest, DiscoverEntryPoints_SubroutinePrologues_6502) {
  // Test: Scan for PHP/PHA patterns
  // Expected: Subroutines at addresses with PHP/PHA discovered
}

TEST_F(CodeAnalyzerTest, DiscoverEntryPoints_LEA_Targets) {
  // Test: 6809 LEA X,PCR instructions create code pointers
  // Expected: LEA targets discovered as entry points
}

TEST_F(CodeAnalyzerTest, DiscoverEntryPoints_EmptyBinary) {
  // Test: Binary with no recognizable entry points
  // Expected: No crashes, graceful handling
}
```

##### 1.2 Code Flow Analysis (5-6 hours)
Test recursive traversal and code discovery:

```cpp
TEST_F(CodeAnalyzerTest, AnalyzeRecursively_LinearCode) {
  // Test: Simple linear code (LDA, STA, RTS)
  // Expected: All instructions discovered in one pass
}

TEST_F(CodeAnalyzerTest, AnalyzeRecursively_SimpleBranch) {
  // Test: Code with BEQ/BNE branches
  // Expected: Both taken/not-taken paths discovered
}

TEST_F(CodeAnalyzerTest, AnalyzeRecursively_JSR_RTS) {
  // Test: Main routine calls subroutine
  // Expected: Both routines fully disassembled
}

TEST_F(CodeAnalyzerTest, AnalyzeRecursively_MultipleJumps) {
  // Test: Code with JMP instructions
  // Expected: Jump targets discovered
}

TEST_F(CodeAnalyzerTest, AnalyzeRecursively_IndirectJump) {
  // Test: JMP (indirect) - cannot statically analyze
  // Expected: Stops at indirect jump, marks as computed
}

TEST_F(CodeAnalyzerTest, AnalyzeRecursively_LoopDetection) {
  // Test: Code with infinite loop (BRA $)
  // Expected: Detects loop, doesn't hang
}

TEST_F(CodeAnalyzerTest, AnalyzeRecursively_MaxInstructionLimit) {
  // Test: Binary larger than MAX_INSTRUCTIONS
  // Expected: Stops gracefully at limit
}
```

##### 1.3 Data Detection & Heuristics (3-4 hours)
Test data vs code discrimination:

```cpp
TEST_F(CodeAnalyzerTest, DataHeuristics_PrintableStrings) {
  // Test: Region with "HELLO WORLD\0" string
  // Expected: Classified as DATA, not CODE
}

TEST_F(CodeAnalyzerTest, DataHeuristics_BitmapData) {
  // Test: Region with bitmap patterns (graphics)
  // Expected: Classified as DATA based on entropy
}

TEST_F(CodeAnalyzerTest, DataHeuristics_RepeatedBytes) {
  // Test: Region with $00 $00 $00... pattern
  // Expected: Classified as DATA
}

TEST_F(CodeAnalyzerTest, DataHeuristics_AddressTable) {
  // Test: Region with 16-bit address pairs
  // Expected: Could be jump table or data
}

TEST_F(CodeAnalyzerTest, LooksLikeData_MixedContent) {
  // Test: Region with code-like bytes intermixed with data
  // Expected: Correct classification based on dominant pattern
}
```

##### 1.4 Reclassification Logic (3-4 hours)
Test conservative reclassification:

```cpp
TEST_F(CodeAnalyzerTest, ReclassifyAfterComputedJumps) {
  // Test: Code region unreachable after JMP (indirect)
  // Expected: Unreachable code reclassified conservatively
}

TEST_F(CodeAnalyzerTest, ReclassifyMixedCodeDataRegions) {
  // Test: Region initially marked CODE but looks like DATA
  // Expected: Reclassified if heuristics agree (2+ matches)
}

TEST_F(CodeAnalyzerTest, ReclassifyProtectsXrefs) {
  // Test: Region with cross-references should NOT be reclassified
  // Expected: Cross-referenced addresses remain CODE
}

TEST_F(CodeAnalyzerTest, ReclassifyDataRegions_ToCode) {
  // Test: DATA region discovered to contain reachable code
  // Expected: Reclassified to CODE on subsequent pass
}
```

#### Test Setup Pattern

```cpp
class CodeAnalyzerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Create test binary
    binary_ = std::make_unique<core::Binary>();
    address_map_ = std::make_unique<core::AddressMap>();
  }

  void CreateTestBinary(const std::vector<uint8_t>& data, uint32_t load_addr) {
    binary_->set_data(data);
    binary_->set_load_address(load_addr);
  }

  void RunAnalysis(cpu::CpuVariant variant) {
    auto cpu = cpu::CreateCpu(variant);
    analysis::CodeAnalyzer analyzer(cpu.get(), binary_.get());
    analyzer.Analyze(address_map_.get());
  }

  std::unique_ptr<core::Binary> binary_;
  std::unique_ptr<core::AddressMap> address_map_;
};
```

---

### Phase 2: EdtasmFormatter Tests (HIGH PRIORITY)

**Goal**: Increase EdtasmFormatter coverage from 0% → 85%
**Impact**: +8.6% overall coverage (58% → 66.6%)
**Effort**: 6-8 hours

#### Test File
**Create**: `tests/test_edtasm_formatter.cpp`

#### Test Structure
Mirror existing `test_merlin_formatter.cpp` and `test_scmasm_formatter.cpp` structure:

```cpp
TEST_F(EdtasmFormatterTest, FormatterName) { }
TEST_F(EdtasmFormatterTest, FormatHeader) { }
TEST_F(EdtasmFormatterTest, FormatFooter) { }
TEST_F(EdtasmFormatterTest, FormatImpliedInstruction) { }
TEST_F(EdtasmFormatterTest, FormatImmediateInstruction) { }
TEST_F(EdtasmFormatterTest, FormatAbsoluteInstruction) { }
TEST_F(EdtasmFormatterTest, FormatIndexedInstruction) { }
TEST_F(EdtasmFormatterTest, FormatDirectInstruction) { }
TEST_F(EdtasmFormatterTest, FormatExtendedInstruction) { }
TEST_F(EdtasmFormatterTest, FormatInstructionWithLabel) { }
TEST_F(EdtasmFormatterTest, FormatInstructionWithComment) { }
TEST_F(EdtasmFormatterTest, FormatBranchWithLabel) { }
TEST_F(EdtasmFormatterTest, FormatDataFCB) { }
TEST_F(EdtasmFormatterTest, FormatDataFDB) { }
TEST_F(EdtasmFormatterTest, FormatDataFCC) { }
TEST_F(EdtasmFormatterTest, FormatCompleteProgram) { }
TEST_F(EdtasmFormatterTest, ColumnAlignment) { }
TEST_F(EdtasmFormatterTest, SymbolTableIntegration) { }
TEST_F(EdtasmFormatterTest, EmptyInstructions) { }
```

#### Key EDTASM-Specific Tests

```cpp
TEST_F(EdtasmFormatterTest, DirectivesEDTASM) {
  // Test EDTASM-specific directives:
  // ORG, END, RMB, FCB, FDB, FCC, EQU
}

TEST_F(EdtasmFormatterTest, LineNumbering) {
  // Test: EDTASM may have line number format
  // Verify correct numbering if implemented
}

TEST_F(EdtasmFormatterTest, IndexedAddressing_6809) {
  // Test: ,X, ,Y, ,U, ,S and all 6809 indexed modes
  // Expected: Correct EDTASM syntax
}

TEST_F(EdtasmFormatterTest, PSHSPULSFormat) {
  // Test: PSHS D,X,Y,U,PC formatting
  // Expected: Comma-separated register list
}
```

---

### Phase 3: CPU Plugin Tests (HIGH PRIORITY)

**Goal**: Increase CPU plugin coverage to 85%
**Impact**: +7% overall coverage (66.6% → 73.6%)
**Effort**: 10-12 hours

#### 3.1 CPU 6809 Tests (5-6 hours)

**Enhance**: `tests/test_cpu_6809.cpp` (create if doesn't exist)

##### Indexed Addressing Mode Tests

```cpp
TEST_F(Cpu6809Test, IndexedMode_ConstantOffset) {
  // ,R with 5-bit, 8-bit, 16-bit offsets
  uint8_t lda_x_0 [] = {0xA6, 0x84};  // LDA ,X
  uint8_t lda_x_5 [] = {0xA6, 0x85};  // LDA 5,X
  uint8_t lda_x_ff[] = {0xA6, 0x88, 0xFF};  // LDA $FF,X
  // ... test all variants
}

TEST_F(Cpu6809Test, IndexedMode_Accumulator) {
  // A,R and B,R and D,R modes
  uint8_t lda_a_x[] = {0xA6, 0x86};  // LDA A,X
  uint8_t lda_b_x[] = {0xA6, 0x85};  // LDA B,X
  // ... test all
}

TEST_F(Cpu6809Test, IndexedMode_AutoIncrement) {
  // ,R+ and ,R++ modes
  uint8_t lda_x_inc [] = {0xA6, 0x80};  // LDA ,X+
  uint8_t lda_x_inc2[] = {0xA6, 0x81};  // LDA ,X++
  // ... test all
}

TEST_F(Cpu6809Test, IndexedMode_AutoDecrement) {
  // ,-R and ,--R modes
}

TEST_F(Cpu6809Test, IndexedMode_PCRelative) {
  // 8-bit and 16-bit PC-relative
  uint8_t lda_pcr_8 [] = {0xA6, 0x8C, 0x10};  // LDA $10,PCR
  uint8_t lda_pcr_16[] = {0xA6, 0x8D, 0x12, 0x34};  // LDA $1234,PCR
}

TEST_F(Cpu6809Test, IndexedMode_Indirect) {
  // [,R] indirect modes
  uint8_t lda_ind[] = {0xA6, 0x94};  // LDA [,X]
}

TEST_F(Cpu6809Test, IndexedMode_Extended) {
  // [addr] extended indirect
}
```

##### 6809 Instruction Coverage

```cpp
TEST_F(Cpu6809Test, AllBranchInstructions) {
  // BRA, BRN, BHI, BLS, BCC, BCS, BNE, BEQ,
  // BVC, BVS, BPL, BMI, BGE, BLT, BGT, BLE
  // Test both short and long branches
}

TEST_F(Cpu6809Test, TwoByteOpcodes) {
  // Page 2 ($10xx) and Page 3 ($11xx) opcodes
  // LBRN, LBHI, LBCC, CMPD, CMPY, LDY, etc.
}

TEST_F(Cpu6809Test, PushPullInstructions) {
  // PSHS, PULS, PSHU, PULU with all register combinations
}

TEST_F(Cpu6809Test, TransferExchange) {
  // TFR, EXG with all register pairs
}

TEST_F(Cpu6809Test, ArithmeticInstructions) {
  // ADDA, ADDB, ADDD, SUBA, SUBB, SUBD
  // MUL, DAA, NEG, COM
}

TEST_F(Cpu6809Test, LogicalInstructions) {
  // ANDA, ANDB, ORA, ORB, EORA, EORB
  // ANDCC, ORCC
}

TEST_F(Cpu6809Test, ShiftRotateInstructions) {
  // ASL, ASR, LSL, LSR, ROL, ROR
}

TEST_F(Cpu6809Test, LEA_Instructions) {
  // LEAX, LEAY, LEAU, LEAS
  // Critical for entry point discovery
}

TEST_F(Cpu6809Test, InsufficientData) {
  // Test all opcodes with insufficient bytes
}

TEST_F(Cpu6809Test, IllegalOpcodes) {
  // Test undefined opcodes: $01, $02, $05, etc.
}
```

##### 6809 CPU State Tests

```cpp
TEST_F(CpuState6809Test, ExecuteInstruction_AllALU) {
  // Test A, B register operations
}

TEST_F(CpuState6809Test, ExecuteInstruction_IndexRegisters) {
  // Test X, Y, U, S operations
}

TEST_F(CpuState6809Test, ExecuteInstruction_PushPull) {
  // Test stack operations
}

TEST_F(CpuState6809Test, EvaluateBranchCondition_AllBranches) {
  // Test all 16 branch conditions with various flag states
  // Critical for execution simulator accuracy
}

TEST_F(CpuState6809Test, FlagCalculation_Arithmetic) {
  // Test N, Z, V, C flag calculation for all arithmetic ops
}
```

#### 3.2 CPU 6502 Tests (4-5 hours)

**Enhance**: `tests/test_cpu_6502.cpp` (already exists, add missing coverage)

##### Missing 6502 Tests

```cpp
TEST_F(Cpu6502Test, CPU_State_ExecuteAllInstructions) {
  // Test execution of all 6502 instructions through CpuState6502
  // Currently many execution paths untested
}

TEST_F(Cpu6502Test, FlagCalculation_ADC_SBC) {
  // Test carry, overflow, negative, zero flags
}

TEST_F(Cpu6502Test, DecimalMode_BCD) {
  // Test ADC/SBC in decimal mode (D flag set)
}

TEST_F(Cpu6502Test, InsufficientData_AllModes) {
  // Ensure all addressing modes handle truncated data
}

TEST_F(Cpu6502Test, C02_ExtendedInstructions) {
  // Test all 65C02-specific opcodes
  // BRA, PHX, PHY, PLX, PLY, STZ, TRB, TSB, etc.
}
```

---

### Phase 4: EquateGenerator Tests (MEDIUM PRIORITY)

**Goal**: Increase EquateGenerator coverage from 0% → 85%
**Impact**: +1.5% overall coverage (73.6% → 75.1%)
**Effort**: 3-4 hours

#### Test File
**Create**: `tests/test_equate_generator.cpp`

#### Test Scenarios

```cpp
TEST_F(EquateGeneratorTest, GenerateEquates_NoSymbols) {
  // Test: Disassembly with no symbol table
  // Expected: Common hardware addresses get equates (e.g., $FFD0-$FFDF for CoCo)
}

TEST_F(EquateGeneratorTest, GenerateEquates_WithSymbolTable) {
  // Test: Symbol table with known addresses
  // Expected: Use symbol names instead of hex
}

TEST_F(EquateGeneratorTest, GenerateEquates_ZeroPage) {
  // Test: 6502 zero page addresses ($00-$FF)
  // Expected: Generate ZP_ prefixed equates for frequently used addresses
}

TEST_F(EquateGeneratorTest, GenerateEquates_IOPorts) {
  // Test: Common I/O addresses for CoCo ($FF00-$FFFF)
  // Expected: PIA, SAM, GIME equates
}

TEST_F(EquateGeneratorTest, GenerateEquates_Apple2) {
  // Test: Apple II I/O addresses ($C000-$CFFF)
  // Expected: Common Apple II ROM/I/O equates
}

TEST_F(EquateGeneratorTest, FormatEquates_Merlin) {
  // Test: Equate formatting for Merlin assembler
  // Expected: "LABEL    EQU    $1234" format
}

TEST_F(EquateGeneratorTest, FormatEquates_EDTASM) {
  // Test: Equate formatting for EDTASM+ assembler
  // Expected: "LABEL    EQU    $1234" format
}

TEST_F(EquateGeneratorTest, FormatEquates_SCMASM) {
  // Test: Equate formatting for SCMASM assembler
  // Expected: Line number + equate statement
}

TEST_F(EquateGeneratorTest, DeduplicateEquates) {
  // Test: Multiple references to same address
  // Expected: Only one equate generated
}

TEST_F(EquateGeneratorTest, EquateOrdering) {
  // Test: Equates should be sorted by address
  // Expected: Ascending address order
}
```

---

### Phase 5: Formatter Integration Tests (MEDIUM PRIORITY)

**Goal**: Increase MerlinFormatter and ScmasmFormatter coverage to 85%
**Impact**: +3% overall coverage (75.1% → 78.1%)
**Effort**: 4-5 hours

#### 5.1 Enhance Merlin Tests (2-3 hours)

**Modify**: `tests/test_merlin_formatter.cpp`

```cpp
TEST_F(MerlinFormatterTest, FormatEquates_MultipleSections) {
  // Test: Equates at beginning, data in middle, code at end
}

TEST_F(MerlinFormatterTest, FormatDataRegion_StringWithEscapes) {
  // Test: Strings with quotes, control characters
}

TEST_F(MerlinFormatterTest, FormatDataRegion_MixedData) {
  // Test: Bytes, words, strings intermixed
}

TEST_F(MerlinFormatterTest, ComplexProgram_WithXrefs) {
  // Test: Full program with cross-references, multiple subroutines
}

TEST_F(MerlinFormatterTest, LabelSubstitution_AllModes) {
  // Test: Label substitution in all addressing modes
}

TEST_F(MerlinFormatterTest, CommentWrapping) {
  // Test: Very long comments should wrap or truncate
}

TEST_F(MerlinFormatterTest, ASCIIData_Printable) {
  // Test: ASC directive for printable strings
}

TEST_F(MerlinFormatterTest, ASCIIData_NonPrintable) {
  // Test: HEX directive for non-printable bytes
}
```

#### 5.2 Enhance SCMASM Tests (2 hours)

**Modify**: `tests/test_scmasm_formatter.cpp`

```cpp
TEST_F(ScmasmFormatterTest, LineNumbering_Sequential) {
  // Test: Line numbers increment correctly
}

TEST_F(ScmasmFormatterTest, LineNumbering_Gaps) {
  // Test: Line number gaps (10, 20, 30, ...)
}

TEST_F(ScmasmFormatterTest, ComplexProgram_WithLineNumbers) {
  // Test: Full program with proper line numbering
}

TEST_F(ScmasmFormatterTest, DataDirectives_AllTypes) {
  // Test: .DB, .DW, .AS, .TF directives
}
```

---

### Phase 6: Execution Simulator Tests (MEDIUM PRIORITY)

**Goal**: Increase ExecutionSimulator coverage from 65% → 85%
**Impact**: +0.4% overall coverage (78.1% → 78.5%)
**Effort**: 2-3 hours

#### Enhance Existing Tests

**Modify**: `tests/test_execution_simulator_enhanced.cpp`

```cpp
TEST_F(ExecutionSimulatorTest, SimulateFrom_MaxInstructionLimit) {
  // Test: Simulation stops at max instruction count
}

TEST_F(ExecutionSimulatorTest, SimulateFrom_LoopDetection) {
  // Test: Infinite loop detected and stopped
}

TEST_F(ExecutionSimulatorTest, SimulateFrom_IllegalInstruction) {
  // Test: Stops gracefully on illegal opcode
}

TEST_F(ExecutionSimulatorTest, SimulateFrom_OutOfBounds) {
  // Test: PC goes outside binary bounds
}

TEST_F(ExecutionSimulatorTest, ExecuteInstruction_MemoryAccess) {
  // Test: Memory read/write callbacks
}

TEST_F(ExecutionSimulatorTest, DiscoveredAddresses_BranchPaths) {
  // Test: Both branch taken/not taken are discovered
}

TEST_F(ExecutionSimulatorTest, DiscoveredAddresses_ConditionalJumps) {
  // Test: Conditional branches with known flag states
}
```

---

### Phase 7: Remaining Components (LOW PRIORITY)

**Goal**: Address final coverage gaps
**Impact**: +6.5% overall coverage (78.5% → 85%)
**Effort**: 5-7 hours

#### 7.1 Symbol Table Tests (1 hour)
Currently 24% coverage, needs better testing:

```cpp
TEST_F(SymbolTableTest, LoadFromFile_Complex) {
  // Test: Load large symbol table from JSON
}

TEST_F(SymbolTableTest, LookupPerformance) {
  // Test: Lookup time for 1000+ symbols
}
```

#### 7.2 Binary Tests (1 hour)
Currently 56% coverage:

```cpp
TEST_F(BinaryTest, LoadFromFile_LargeFile) {
  // Test: Load 64KB binary
}

TEST_F(BinaryTest, LoadFromFile_Corrupted) {
  // Test: Handle corrupted file gracefully
}
```

#### 7.3 Disk Extractors (2-3 hours)
Not measured in current report - may need tests:

```cpp
TEST_F(CoCoExtractorTest, ExtractDSKImage) {
  // Test: Extract binary from CoCo DSK
}

TEST_F(ACXExtractorTest, ExtractCartridge) {
  // Test: Extract ROM from ACX cartridge format
}
```

#### 7.4 Integration Tests (2-3 hours)
End-to-end testing:

```cpp
TEST_F(IntegrationTest, DisassembleZAXXON) {
  // Test: Full disassembly of ZAXXON.BIN
  // Expected: 98.6% coverage maintained
}

TEST_F(IntegrationTest, DisassembleApple2ROM) {
  // Test: Apple II ROM disassembly
}

TEST_F(IntegrationTest, DisassembleWithHints) {
  // Test: Load hints file, verify application
}

TEST_F(IntegrationTest, OutputToFile) {
  // Test: Write disassembly to file, verify format
}
```

---

## Execution Strategy

### Recommended Order

1. **Phase 1** (CodeAnalyzer) - Highest impact, most critical component
2. **Phase 2** (EdtasmFormatter) - Second highest impact, currently 0%
3. **Phase 3** (CPU Plugins) - Foundation for all analysis
4. **Phase 4** (EquateGenerator) - Quick win, fills gap
5. **Phase 5** (Formatters) - Polish existing tests
6. **Phase 6** (ExecutionSimulator) - Small gap to close
7. **Phase 7** (Remaining) - Final push to 85%

### Testing After Each Phase

```bash
# Rebuild with coverage
cd build_coverage
cmake -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_CXX_FLAGS="--coverage -fprofile-arcs -ftest-coverage" \
      -DCMAKE_EXE_LINKER_FLAGS="--coverage" \
      -DBUILD_TESTING=ON ..
cmake --build . -j8

# Run tests
ctest --output-on-failure

# Measure coverage
python3 /tmp/coverage.py

# Verify increase
# Expected after each phase:
# Phase 1: ~58%
# Phase 2: ~67%
# Phase 3: ~74%
# Phase 4: ~75%
# Phase 5: ~78%
# Phase 6: ~79%
# Phase 7: ~85%
```

---

## Expected Timeline

| Phase | Hours | Coverage Gain | Cumulative |
|-------|-------|---------------|------------|
| Phase 1: CodeAnalyzer | 15-20 | +18% | 58% |
| Phase 2: EdtasmFormatter | 6-8 | +8.6% | 67% |
| Phase 3: CPU Plugins | 10-12 | +7% | 74% |
| Phase 4: EquateGenerator | 3-4 | +1.5% | 75% |
| Phase 5: Formatters | 4-5 | +3% | 78% |
| Phase 6: ExecutionSim | 2-3 | +0.4% | 79% |
| Phase 7: Remaining | 5-7 | +6% | **85%** |
| **TOTAL** | **45-59** | **+45%** | **85%** ✅ |

**Estimated completion**: 1-1.5 weeks of focused work

---

## Success Criteria

### Quantitative Targets

- ✅ Overall coverage: **80-90%** (target: 85%)
- ✅ CodeAnalyzer: **≥80%**
- ✅ All formatters: **≥80%**
- ✅ CPU plugins: **≥80%**
- ✅ All analysis modules: **≥80%**
- ✅ All tests pass: **225/225** (100%)

### Qualitative Targets

- ✅ Integration tests cover end-to-end workflows
- ✅ Edge cases handled (empty binaries, corrupted data, etc.)
- ✅ Performance tests for large binaries (64KB+)
- ✅ All public APIs have test coverage
- ✅ Critical paths (code flow analysis, entry point discovery) thoroughly tested

---

## Risk Mitigation

### High-Risk Areas

1. **CodeAnalyzer complexity** - 1,520 lines, many algorithms
   - Mitigation: Break into focused test suites per algorithm
   - Test each analysis pass independently

2. **CPU plugin instruction coverage** - 200+ opcodes per CPU
   - Mitigation: Use parameterized tests for opcode tables
   - Auto-generate tests from opcode definitions

3. **Time investment** - 45-59 hours total
   - Mitigation: Prioritize phases, can stop at 80% if needed
   - Phases 1-3 get to 74%, acceptable if time-constrained

### Test Maintenance

- Keep tests focused and independent
- Use fixtures to reduce duplication
- Document test intent clearly
- Maintain test binaries in `tests/binaries/` directory

---

## Next Steps

**Immediate action**: Start Phase 1 (CodeAnalyzer Integration Tests)

1. Create `tests/test_code_analyzer_integration.cpp`
2. Implement entry point discovery tests
3. Build and verify coverage increases
4. Proceed to code flow analysis tests
5. Continue through all Phase 1 test categories

**Ready to begin?** 🚀
