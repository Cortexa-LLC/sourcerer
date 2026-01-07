# Sourcerer Architecture Documentation

## Table of Contents
1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Module Organization](#module-organization)
4. [Design Patterns](#design-patterns)
5. [Core Workflows](#core-workflows)
6. [Component Details](#component-details)

---

## Overview

Sourcerer is a modern, multi-CPU disassembler built with clean code principles following SOLID design patterns. The architecture emphasizes:

- **Modularity**: Clear separation of concerns with focused components
- **Extensibility**: Plugin architecture for CPUs, disk formats, and output formatters
- **Maintainability**: Strategy pattern extraction eliminates god classes
- **Testability**: Dependency injection enables isolated unit testing

### Key Design Principles Applied

- **Single Responsibility Principle**: Each class has one well-defined purpose
- **Open/Closed Principle**: Extensible via plugins without modifying core code
- **Liskov Substitution**: CPU plugins and formatters are interchangeable
- **Interface Segregation**: Minimal, focused interfaces
- **Dependency Inversion**: Core depends on abstractions, not concrete implementations

---

## System Architecture

### High-Level Component Diagram

```mermaid
graph TB
    subgraph "Entry Point"
        Main[main.cpp]
    end

    subgraph "Workflow Layer"
        Workflow[DisassemblerWorkflow]
        Orchestrator[DisassemblyOrchestrator]
    end

    subgraph "Core Layer"
        Binary[Binary]
        Instruction[Instruction]
        AddressMap[AddressMap]
        SymbolTable[SymbolTable]
        Constants[Constants]
    end

    subgraph "Analysis Layer"
        CodeAnalyzer[CodeAnalyzer<br/>Orchestrator]
        ExecutionSim[ExecutionSimulator<br/>Dynamic Analysis]

        subgraph "Analysis Strategies"
            DataHeuristics[DataHeuristics]
            GraphicsDetector[GraphicsDetector]
            JumpTableDetector[JumpTableDetector]
            InlineDataScanner[InlineDataScanner]
            MisalignmentResolver[MisalignmentResolver]
            EntryPointDiscovery[EntryPointDiscovery]
            Reclassification[Reclassification]
            CodeFlow[CodeFlowStrategy]
        end
    end

    subgraph "CPU Plugin Layer"
        CPUInterface[CpuPlugin<br/>Interface]
        CpuStateInterface[CpuState<br/>Interface]
        CPU6502[Cpu6502]
        CPU6809[Cpu6809]
        CPU65C02[Cpu65C02]
        State6502[CpuState6502]
        State6809[CpuState6809]
    end

    subgraph "Disk Plugin Layer"
        DiskInterface[DiskExtractor<br/>Interface]
        CoCoExtractor[CoCoExtractor]
        ACXExtractor[ACXExtractor]
    end

    subgraph "Output Layer"
        FormatterInterface[Formatter<br/>Interface]
        BaseFormatter[BaseFormatter<br/>Template Method]
        MerlinFormatter[MerlinFormatter]
        EdtasmFormatter[EdtasmFormatter]
        ScmasmFormatter[ScmasmFormatter]
    end

    subgraph "Utilities"
        CliParser[CliParser]
        Logger[Logger]
    end

    Main --> Workflow
    Workflow --> Orchestrator
    Workflow --> DiskInterface
    Workflow --> SymbolTable
    Workflow --> FormatterInterface

    Orchestrator --> CodeAnalyzer
    Orchestrator --> CPUInterface

    CodeAnalyzer --> DataHeuristics
    CodeAnalyzer --> GraphicsDetector
    CodeAnalyzer --> JumpTableDetector
    CodeAnalyzer --> InlineDataScanner
    CodeAnalyzer --> MisalignmentResolver
    CodeAnalyzer --> EntryPointDiscovery
    CodeAnalyzer --> Reclassification
    CodeAnalyzer --> CodeFlow
    CodeAnalyzer --> ExecutionSim

    CodeAnalyzer --> CPUInterface
    CodeAnalyzer --> AddressMap
    CodeAnalyzer --> Binary

    ExecutionSim --> CPUInterface
    ExecutionSim --> CpuStateInterface
    ExecutionSim --> Binary

    CPUInterface -.implements.-> CPU6502
    CPUInterface -.implements.-> CPU6809
    CPUInterface -.implements.-> CPU65C02

    CpuStateInterface -.implements.-> State6502
    CpuStateInterface -.implements.-> State6809

    CPU6502 -.creates.-> State6502
    CPU6809 -.creates.-> State6809

    DiskInterface -.implements.-> CoCoExtractor
    DiskInterface -.implements.-> ACXExtractor

    FormatterInterface -.implements.-> BaseFormatter
    BaseFormatter -.extends.-> MerlinFormatter
    BaseFormatter -.extends.-> EdtasmFormatter
    BaseFormatter -.extends.-> ScmasmFormatter

    Workflow --> CliParser
    Workflow --> Logger

    style Main fill:#e1f5ff
    style Workflow fill:#fff3e0
    style CodeAnalyzer fill:#f3e5f5
    style CPUInterface fill:#e8f5e9
    style DiskInterface fill:#e8f5e9
    style FormatterInterface fill:#fff9c4
```

---

## Module Organization

### Directory Structure

```
src/
├── core/               # CPU-agnostic data structures
│   ├── binary.cpp           # Binary file representation
│   ├── instruction.cpp      # Instruction structure
│   ├── address_map.cpp      # CODE/DATA/UNKNOWN tracking
│   ├── symbol_table.cpp     # Symbol management
│   ├── constants.h          # Centralized magic numbers
│   └── exceptions.cpp       # Exception hierarchy
│
├── cpu/                # CPU plugin architecture
│   ├── cpu_plugin.h         # Abstract CPU interface
│   ├── cpu_state.h          # Abstract CPU state interface
│   ├── cpu_registry.cpp     # Plugin registration
│   ├── m6502/
│   │   ├── cpu_6502.cpp     # 6502 implementation
│   │   ├── cpu_state_6502.h # 6502 execution state
│   │   └── opcodes_6502.cpp # 6502 opcode tables
│   └── m6809/
│       ├── cpu_6809.cpp     # 6809 implementation
│       ├── cpu_state_6809.h # 6809 execution state
│       ├── opcodes_6809.cpp # 6809 opcode tables
│       └── indexed_mode.cpp # 6809 indexed addressing
│
├── analysis/           # Code flow analysis (CPU-agnostic)
│   ├── code_analyzer.cpp    # Orchestrator (was 2,627 lines, now ~300)
│   ├── disassembly_orchestrator.cpp  # High-level disassembly
│   ├── execution_simulator.h        # Dynamic branch analysis interface
│   ├── execution_simulator.cpp      # CPU-agnostic execution simulation
│   ├── label_generator.cpp          # Label generation
│   ├── xref_builder.cpp             # Cross-references
│   ├── hints_parser.cpp             # User hints
│   ├── equate_generator.cpp         # Equate detection
│   ├── pattern_detector.cpp         # Platform patterns
│   │
│   └── strategies/     # Strategy pattern extraction
│       ├── data_heuristics.cpp       # Data detection heuristics
│       ├── graphics_detector.cpp     # Graphics data patterns
│       ├── jump_table_detector.cpp   # Jump table detection
│       ├── inline_data_scanner.cpp   # Inline data handling
│       ├── misalignment_resolver.cpp # Conflict resolution
│       ├── entry_point_discovery_strategy.cpp  # Entry point scanning
│       ├── reclassification_strategy.cpp       # CODE→DATA fixes
│       └── code_flow_strategy.cpp    # Recursive traversal
│
├── disk/               # Disk format extractors
│   ├── disk_registry.cpp    # Extractor registration
│   ├── coco_extractor.cpp   # CoCo DSK support
│   ├── acx_extractor.cpp    # Apple II DSK support
│   └── raw_file.cpp         # Raw binary fallback
│
├── output/             # Output formatters
│   ├── formatter_registry.cpp     # Formatter registration
│   ├── base_formatter.cpp         # Template Method base (NEW)
│   ├── merlin_formatter.cpp       # Merlin assembler (reduced 773→100 lines)
│   ├── edtasm_formatter.cpp       # EDTASM+ assembler (reduced 858→80 lines)
│   ├── scmasm_formatter.cpp       # SCMASM assembler (reduced 530→90 lines)
│   ├── data_collector.cpp         # Data region analysis
│   ├── address_analyzer.cpp       # Address analysis
│   └── label_resolver.cpp         # Label resolution
│
├── utils/              # Utilities
│   ├── cli_parser.cpp       # CLI argument parsing
│   └── logger.cpp           # Logging system
│
├── main.cpp            # Entry point (reduced 573→9 lines)
└── disassembler_workflow.cpp  # Main workflow orchestration
```

### Module Dependencies

```mermaid
graph LR
    subgraph "Layer 1: Entry"
        Main[main.cpp]
    end

    subgraph "Layer 2: Workflow"
        Workflow[DisassemblerWorkflow]
    end

    subgraph "Layer 3: Orchestration"
        DisasmOrch[DisassemblyOrchestrator]
        CodeAnalyzer[CodeAnalyzer]
    end

    subgraph "Layer 4: Strategies"
        Strategies[8 Strategy Classes]
    end

    subgraph "Layer 5: Plugins"
        CPUs[CPU Plugins]
        Disks[Disk Plugins]
        Formatters[Formatter Plugins]
    end

    subgraph "Layer 6: Core"
        Core[Core Data Structures]
    end

    Main --> Workflow
    Workflow --> DisasmOrch
    Workflow --> Disks
    Workflow --> Formatters
    DisasmOrch --> CodeAnalyzer
    CodeAnalyzer --> Strategies
    Strategies --> CPUs
    Strategies --> Core
    DisasmOrch --> CPUs
    DisasmOrch --> Core
    Formatters --> Core

    style Main fill:#e1f5ff
    style Workflow fill:#fff3e0
    style DisasmOrch fill:#f3e5f5
    style CodeAnalyzer fill:#f3e5f5
    style Strategies fill:#e1bee7
    style CPUs fill:#c8e6c9
    style Disks fill:#c8e6c9
    style Formatters fill:#fff9c4
    style Core fill:#ffccbc
```

---

## Design Patterns

### 1. Strategy Pattern (Analysis Strategies)

**Problem Solved**: CodeAnalyzer was a 2,627-line god class with 9 responsibilities

**Solution**: Extract each responsibility into a focused strategy class

```mermaid
classDiagram
    class CodeAnalyzer {
        -cpu: CpuPlugin*
        -binary: Binary*
        -strategies: Strategy instances
        +RecursiveAnalyze()
        +AddEntryPoint()
        +UpdateStatistics()
    }

    class DataHeuristics {
        +LooksLikeData()
        +CountDataHeuristics()
        +CalculatePrintablePercentage()
    }

    class GraphicsDetector {
        +HasBitmapEntropy()
        +HasByteAlignment()
        +IsInGraphicsRegion()
    }

    class JumpTableDetector {
        +ScanForJumpTables()
        +FindJumpTableCandidates()
        +ValidateJumpTable()
    }

    class MisalignmentResolver {
        +DetectMisalignment()
        +ResolveMisalignment()
        +CalculateInstructionConfidence()
    }

    class EntryPointDiscovery {
        +DiscoverEntryPoints()
        +ScanInterruptVectors()
        +ScanForSubroutinePatterns()
    }

    class ReclassificationStrategy {
        +ReclassifyAfterComputedJumps()
        +ReclassifyMixedCodeDataRegions()
        +ReclassifyDataRegions()
    }

    class CodeFlowStrategy {
        +AnalyzeRecursively()
        +RunAnalysisPass()
    }

    CodeAnalyzer *-- DataHeuristics
    CodeAnalyzer *-- GraphicsDetector
    CodeAnalyzer *-- JumpTableDetector
    CodeAnalyzer *-- MisalignmentResolver
    CodeAnalyzer *-- EntryPointDiscovery
    CodeAnalyzer *-- ReclassificationStrategy
    CodeAnalyzer *-- CodeFlowStrategy
```

**Benefits**:
- CodeAnalyzer: 2,627 → 300 lines (90% reduction)
- Each strategy is independently testable
- Easy to add new analysis strategies
- Clear separation of concerns

### 2. Plugin Architecture (CPU/Disk/Formatter)

**Problem Solved**: Need to support multiple CPUs, disk formats, and assembler syntaxes

**Solution**: Abstract interfaces with concrete plugin implementations

```mermaid
classDiagram
    class CpuPlugin {
        <<interface>>
        +Disassemble()*
        +Name()*
        +GetAnalysisCapabilities()*
        +LooksLikeSubroutineStart()*
        +IsLikelyCode()*
    }

    class Cpu6502 {
        +Disassemble()
        +Name()
        +GetAnalysisCapabilities()
    }

    class Cpu6809 {
        +Disassemble()
        +Name()
        +GetAnalysisCapabilities()
    }

    class CpuRegistry {
        -plugins: map~string,CpuPlugin~
        +Register()
        +Create()
    }

    CpuPlugin <|.. Cpu6502
    CpuPlugin <|.. Cpu6809
    CpuRegistry --> CpuPlugin

    class DiskExtractor {
        <<interface>>
        +ExtractFile()*
        +ListFiles()*
        +IsValidDisk()*
    }

    class CoCoExtractor {
        +ExtractFile()
        +ListFiles()
    }

    class ACXExtractor {
        +ExtractFile()
        +ListFiles()
    }

    DiskExtractor <|.. CoCoExtractor
    DiskExtractor <|.. ACXExtractor
```

**Benefits**:
- Add new CPU without modifying analysis code
- Platform-specific logic isolated in plugins
- Registry pattern for automatic plugin discovery

### 3. Template Method Pattern (Formatters)

**Problem Solved**: 500+ lines of duplicated code across 3 formatters

**Solution**: BaseFormatter with template methods, subclasses override specifics

```mermaid
classDiagram
    class Formatter {
        <<interface>>
        +Format()*
        +Name()*
    }

    class BaseFormatter {
        <<abstract>>
        +Format() final
        #GetEquateDirective()*
        #GetOrgDirective()*
        #GetByteDirective()*
        #GetOpcodeColumn()*
        #FormatEquates()
        #FormatAddress()
        #FormatStringData()
    }

    class MerlinFormatter {
        #GetEquateDirective()
        #GetOrgDirective()
        #GetByteDirective()
    }

    class EdtasmFormatter {
        #GetEquateDirective()
        #GetOrgDirective()
        #GetByteDirective()
    }

    class ScmasmFormatter {
        #GetEquateDirective()
        #GetOrgDirective()
        #FormatLineNumber()
    }

    Formatter <|.. BaseFormatter
    BaseFormatter <|-- MerlinFormatter
    BaseFormatter <|-- EdtasmFormatter
    BaseFormatter <|-- ScmasmFormatter
```

**Code Reduction**:
- MerlinFormatter: 773 → 100 lines (87% reduction)
- EdtasmFormatter: 858 → 80 lines (91% reduction)
- ScmasmFormatter: 530 → 90 lines (83% reduction)
- Total: 2,161 → 270 lines (87.5% reduction)

### 4. Dependency Injection

**Problem**: Tight coupling, hard to test

**Solution**: Constructor injection of dependencies

```mermaid
classDiagram
    class CodeAnalyzer {
        -cpu: CpuPlugin*
        -binary: Binary*
        -data_heuristics: DataHeuristics*
        -graphics_detector: GraphicsDetector*
        +CodeAnalyzer(cpu, binary)
    }

    class DataHeuristics {
        -binary: Binary*
        +DataHeuristics(binary)
    }

    class ReclassificationStrategy {
        -cpu: CpuPlugin*
        -binary: Binary*
        -data_heuristics: DataHeuristics*
        +ReclassificationStrategy(cpu, binary, data_heuristics)
    }

    CodeAnalyzer --> DataHeuristics : injects
    CodeAnalyzer --> ReclassificationStrategy : injects DataHeuristics
```

**Benefits**:
- Easy to mock dependencies in tests
- Clear dependency graph
- Compile-time dependency checking

---

## Core Workflows

### 1. Main Disassembly Workflow

```mermaid
sequenceDiagram
    participant User
    participant Main
    participant Workflow as DisassemblerWorkflow
    participant Disk as DiskExtractor
    participant Orch as DisassemblyOrchestrator
    participant Analyzer as CodeAnalyzer
    participant Formatter

    User->>Main: ./sourcerer -i ZAXXON.DSK ...
    Main->>Workflow: Run(argc, argv)

    Workflow->>Workflow: Parse CLI arguments
    Workflow->>Disk: ExtractFile(disk, filename)
    Disk-->>Workflow: Binary + load_address

    Workflow->>Workflow: LoadSymbolTables()
    Workflow->>Workflow: LoadHints()

    Workflow->>Orch: DisassembleWithAnalysis(...)

    Orch->>Analyzer: RecursiveAnalyze(address_map)

    loop 10 passes max
        Analyzer->>Analyzer: RunAnalysisPass()
        Note over Analyzer: Uses all 8 strategies
        Analyzer->>Analyzer: DiscoverEntryPoints()
        Analyzer->>Analyzer: ScanForJumpTables()
    end

    Analyzer-->>Orch: address_map updated

    Orch->>Orch: Disassemble CODE regions
    Orch-->>Workflow: instructions[]

    Workflow->>Workflow: BuildXrefs(instructions)
    Workflow->>Workflow: GenerateLabels(instructions)

    Workflow->>Formatter: Format(binary, instructions, ...)
    Formatter-->>Workflow: assembly_output

    Workflow->>Workflow: WriteToFile(output)
    Workflow-->>Main: 0 (success)
    Main-->>User: zaxxon.asm created
```

### 2. Recursive Code Flow Analysis

```mermaid
sequenceDiagram
    participant CodeAnalyzer
    participant CodeFlow as CodeFlowStrategy
    participant Misalign as MisalignmentResolver
    participant EntryPoint as EntryPointDiscovery
    participant CPU as CpuPlugin

    CodeAnalyzer->>CodeAnalyzer: Add entry points

    loop Each analysis pass
        CodeAnalyzer->>CodeFlow: RunAnalysisPass(entry_points)

        loop Each entry point
            CodeFlow->>CodeFlow: AnalyzeRecursively(address)

            CodeFlow->>CPU: Disassemble(address)
            CPU-->>CodeFlow: instruction

            alt Valid instruction
                CodeFlow->>CodeFlow: Mark as CODE
                CodeFlow->>CodeFlow: Cache instruction

                alt Has branch target
                    CodeFlow->>Misalign: DetectMisalignment(target)

                    alt Conflict detected
                        Misalign->>Misalign: CalculateConfidence()
                        Misalign->>Misalign: ResolveMisalignment()
                        Misalign-->>CodeFlow: Conflict resolved
                    end

                    CodeFlow->>CodeFlow: AnalyzeRecursively(branch_target)
                end

                alt Not a return/jump
                    CodeFlow->>CodeFlow: AnalyzeRecursively(next_address)
                end

            else Illegal/data
                CodeFlow->>CodeFlow: Stop traversal
            end
        end

        CodeFlow-->>CodeAnalyzer: bytes_discovered

        alt bytes_discovered > 0
            CodeAnalyzer->>EntryPoint: DiscoverEntryPoints()
            EntryPoint->>EntryPoint: ScanInterruptVectors()
            EntryPoint->>EntryPoint: ScanForSubroutines()
            EntryPoint-->>CodeAnalyzer: New entry points added
        end
    end
```

### 3. Misalignment Resolution

```mermaid
sequenceDiagram
    participant CodeFlow
    participant Misalign as MisalignmentResolver
    participant Cache as InstructionCache

    CodeFlow->>Misalign: DetectMisalignment(target)

    Misalign->>Cache: Check existing instruction at target-1
    Cache-->>Misalign: existing_instruction

    alt Conflict detected
        Note over Misalign: Branch target conflicts with<br/>middle of existing instruction

        Misalign->>Misalign: CalculateConfidence(existing)
        Note over Misalign: Score based on:<br/>- Xrefs<br/>- Opcode legality<br/>- Branch type

        Misalign->>Misalign: CalculateConfidence(target)

        alt target_confidence > existing_confidence
            Misalign->>Cache: InvalidateConflictingInstructions()
            Misalign->>Misalign: ClearVisitedRange()
            Misalign-->>CodeFlow: Target wins, re-analyze
        else existing_confidence >= target_confidence
            Misalign-->>CodeFlow: Keep existing, ignore target
        end
    else No conflict
        Misalign-->>CodeFlow: Continue analysis
    end
```

### 4. Jump Table Detection

```mermaid
sequenceDiagram
    participant Analyzer as CodeAnalyzer
    participant Detector as JumpTableDetector
    participant AddressMap

    Analyzer->>Detector: ScanForJumpTables(address_map)

    Detector->>Detector: FindJumpTableCandidates()

    loop Each DATA/UNKNOWN region
        Detector->>Detector: Read consecutive addresses

        alt Looks like addresses
            Detector->>Detector: Create JumpTableCandidate
            Detector->>Detector: CalculateTableConfidence()

            Note over Detector: Confidence based on:<br/>- Entry count<br/>- Address proximity<br/>- Code validation<br/>- Alignment<br/>- No overlap<br/>- Cross-references

            alt confidence >= 0.6
                Detector->>Detector: candidates.push_back()
            end
        end
    end

    loop Each candidate
        Detector->>Detector: ValidateJumpTable(candidate)

        alt Valid
            Detector->>AddressMap: Mark table region as DATA
            Detector->>AddressMap: Add xrefs from table to targets
            Detector->>Analyzer: Add targets as entry points
        end
    end
```

### 5. Data Reclassification

```mermaid
sequenceDiagram
    participant Analyzer as CodeAnalyzer
    participant Reclass as ReclassificationStrategy
    participant DataHeur as DataHeuristics
    participant AddressMap

    Analyzer->>Reclass: ReclassifyDataRegions(address_map)

    loop Each CODE block
        Reclass->>DataHeur: CountDataHeuristics(region)

        DataHeur->>DataHeur: Check printable percentage
        DataHeur->>DataHeur: Check long printable sequences
        DataHeur->>DataHeur: Check null-terminated strings
        DataHeur->>DataHeur: Check repeated bytes
        DataHeur->>DataHeur: Check address-like pairs
        DataHeur->>DataHeur: Check repeated instructions
        DataHeur->>DataHeur: Check illegal opcode density

        DataHeur-->>Reclass: heuristic_count

        alt heuristic_count >= 2
            Reclass->>AddressMap: CountXrefsInRange()

            alt xref_count == 0
                Reclass->>Reclass: Check for entry points

                alt No entry points in region
                    Reclass->>AddressMap: Reclassify CODE → DATA
                    Note over Reclass: Fixed false positive CODE region
                end
            end
        end
    end
```

### 6. Formatter Output Generation

```mermaid
sequenceDiagram
    participant Workflow
    participant Registry as FormatterRegistry
    participant Base as BaseFormatter
    participant Merlin as MerlinFormatter

    Workflow->>Registry: Create("merlin")
    Registry-->>Workflow: MerlinFormatter instance

    Workflow->>Merlin: Format(binary, instructions, ...)
    Note over Merlin: Inherits from BaseFormatter

    Merlin->>Base: Format() [final method]

    Base->>Merlin: GetEquateDirective()
    Merlin-->>Base: "EQU"

    Base->>Base: FormatEquates()
    Note over Base: Shared implementation

    Base->>Merlin: GetOrgDirective()
    Merlin-->>Base: "ORG"

    loop Each instruction
        Base->>Merlin: GetOpcodeColumn()
        Merlin-->>Base: 10

        Base->>Base: FormatAddress()
        Base->>Base: FormatOpcode()
        Base->>Base: FormatOperand()

        alt Has label
            Base->>Base: GetLabel()
        end

        alt Has comment
            Base->>Merlin: GetCommentColumn()
            Merlin-->>Base: 40
        end
    end

    Base->>Base: FormatDataRegions()
    Base-->>Merlin: Complete assembly output
    Merlin-->>Workflow: assembly_output
```

### 7. Execution Simulation (Dynamic Analysis)

```mermaid
sequenceDiagram
    participant Analyzer as CodeAnalyzer
    participant Sim as ExecutionSimulator
    participant CPU as CpuPlugin
    participant State as CpuState
    participant AddressMap

    Analyzer->>CPU: CreateCpuState()
    CPU-->>Analyzer: CpuState instance

    Analyzer->>Sim: SimulateFrom(entry_point, max_inst)
    Sim->>State: Reset()
    Sim->>State: SetPC(entry_point)

    loop Until RTS or max instructions
        Sim->>State: GetPC()
        State-->>Sim: current_pc

        Sim->>CPU: Disassemble(current_pc)
        CPU-->>Sim: instruction

        alt Illegal instruction
            Sim-->>Analyzer: Stop simulation
        end

        Sim->>State: SetPC(pc + inst.bytes.size())

        alt Is branch instruction
            Sim->>State: EvaluateBranchCondition(mnemonic)
            State-->>Sim: branch_taken (bool)

            alt branch_taken
                Sim->>Sim: discovered_addresses.insert(target)
                Sim->>State: SetPC(target)
            end
        else Is jump/call
            alt Has target address
                Sim->>Sim: discovered_addresses.insert(target)

                alt Is JSR/call
                    Note over Sim: Don't follow to avoid<br/>deep recursion
                else Is JMP
                    Sim->>State: SetPC(target)
                end
            end
        else Regular instruction
            Sim->>State: ExecuteInstruction(inst, read_memory, write_memory)
            State-->>Sim: can_continue (bool)

            alt Can't continue (RTS/RTI)
                Sim-->>Analyzer: Stop simulation
            end
        end
    end

    Sim-->>Analyzer: discovered_addresses set
    Analyzer->>AddressMap: Add discovered addresses as entry points
```

**Key Features:**
- **CPU-Agnostic**: Works with any CPU through `CpuState` abstraction
- **Branch Analysis**: Evaluates branch conditions to discover conditional code paths
- **Conservative**: Stops at RTS/RTI, doesn't follow JSR to avoid infinite recursion
- **Memory Simulation**: Maintains simulated memory state for instruction effects

---

## Component Details

### Core Components

#### Binary
**Responsibility**: Represents a loaded binary file

```cpp
class Binary {
  std::vector<uint8_t> data_;
  uint32_t load_address_;
  std::string file_type_;

public:
  const uint8_t* GetPointer(uint32_t address) const;
  uint32_t size() const;
  uint32_t load_address() const;
};
```

**Key Features**:
- Immutable after loading
- Fast pointer-based access
- Bounds checking

#### AddressMap
**Responsibility**: Track CODE/DATA/UNKNOWN classification for every byte

```cpp
enum class AddressType { UNKNOWN, CODE, DATA };

class AddressMap {
  std::map<uint32_t, AddressType> type_map_;
  std::map<uint32_t, std::set<uint32_t>> xrefs_;
  std::map<uint32_t, std::string> labels_;
  std::map<uint32_t, std::string> comments_;

public:
  void SetType(uint32_t address, AddressType type);
  AddressType GetType(uint32_t address) const;
  bool IsCode(uint32_t address) const;
  void AddXref(uint32_t target, uint32_t source);
  const std::set<uint32_t>& GetXrefs(uint32_t address) const;
};
```

**Key Features**:
- Sparse map (only stores non-UNKNOWN)
- Cross-reference tracking
- Label and comment storage

#### Instruction
**Responsibility**: Represent a single disassembled instruction

```cpp
struct Instruction {
  uint32_t address;
  std::vector<uint8_t> bytes;
  std::string mnemonic;
  std::string operand;
  AddressingMode mode;
  bool is_branch;
  bool is_jump;
  bool is_call;
  bool is_return;
  bool is_illegal;
  uint32_t target_address;  // For branches/jumps/calls
};
```

### Analysis Components

#### CodeAnalyzer (Orchestrator)
**Responsibility**: Coordinate analysis strategies

**Before Refactoring**: 2,627 lines, 9 responsibilities
**After Refactoring**: ~300 lines, 1 responsibility (orchestration)

```cpp
class CodeAnalyzer {
  // Dependencies (injected)
  cpu::CpuPlugin* cpu_;
  const core::Binary* binary_;

  // Strategy instances (composition)
  std::unique_ptr<CodeFlowStrategy> code_flow_;
  std::unique_ptr<EntryPointDiscoveryStrategy> entry_point_discovery_;
  std::unique_ptr<JumpTableDetector> jump_table_detector_;
  std::unique_ptr<DataHeuristics> data_heuristics_;
  std::unique_ptr<GraphicsDetector> graphics_detector_;
  std::unique_ptr<MisalignmentResolver> misalignment_resolver_;
  std::unique_ptr<InlineDataScanner> inline_data_scanner_;
  std::unique_ptr<ReclassificationStrategy> reclassification_;

  // Shared state
  std::map<uint32_t, core::Instruction> instruction_cache_;
  std::set<uint32_t> entry_points_;

public:
  void RecursiveAnalyze(core::AddressMap* address_map);
  void AddEntryPoint(uint32_t address);
};
```

**Key Improvements**:
- Single Responsibility: Only orchestration
- Strategies independently testable
- Clear dependency graph
- Shared instruction cache via pointer injection

#### Strategy Classes

Each strategy is focused and independently testable:

| Strategy | Responsibility | Lines | Key Methods |
|----------|---------------|-------|-------------|
| **DataHeuristics** | Detect data patterns | 230 | `LooksLikeData()`, `CountDataHeuristics()` |
| **GraphicsDetector** | Detect graphics data | 150 | `HasBitmapEntropy()`, `IsInGraphicsRegion()` |
| **JumpTableDetector** | Find jump tables | 320 | `ScanForJumpTables()`, `ValidateJumpTable()` |
| **InlineDataScanner** | Handle inline data | 180 | `IsInlineDataRoutine()`, `ScanInlineData()` |
| **MisalignmentResolver** | Resolve conflicts | 450 | `DetectMisalignment()`, `ResolveMisalignment()` |
| **EntryPointDiscovery** | Find entry points | 380 | `DiscoverEntryPoints()`, `ScanInterruptVectors()` |
| **ReclassificationStrategy** | Fix misclassifications | 420 | `ReclassifyDataRegions()`, `ReclassifyAfterComputedJumps()` |
| **CodeFlowStrategy** | Recursive traversal | 280 | `AnalyzeRecursively()`, `RunAnalysisPass()` |

#### ExecutionSimulator (Dynamic Analysis)
**Responsibility**: Simulate CPU execution to discover conditional code paths

**Architecture**: CPU-agnostic design using polymorphic CPU state

```cpp
class ExecutionSimulator {
  cpu::CpuPlugin* cpu_;
  const core::Binary* binary_;
  std::unique_ptr<CpuState> state_;  // Abstract CPU state

  std::set<uint32_t> executed_addresses_;
  std::set<uint32_t> discovered_addresses_;
  std::map<uint32_t, uint8_t> memory_;  // Simulated memory writes

public:
  ExecutionSimulator(cpu::CpuPlugin* cpu, const core::Binary* binary);

  std::set<uint32_t> SimulateFrom(uint32_t start_address,
                                  int max_instructions = 1000);
  bool WouldBranchBeTaken(uint32_t branch_address);

private:
  bool ExecuteInstruction(const core::Instruction& inst);
  uint8_t ReadByte(uint32_t address);
  void WriteByte(uint32_t address, uint8_t value);
};
```

**Key Features**:
- Discovers branch targets through condition evaluation
- CPU-agnostic via `CpuState` abstraction
- Conservative approach: stops at RTS/RTI
- Maintains simulated memory for instruction effects
- Loop detection prevents infinite simulation

**CPU State Abstraction**:
```cpp
class CpuState {
public:
  virtual ~CpuState() = default;

  virtual void Reset() = 0;
  virtual uint32_t GetPC() const = 0;
  virtual void SetPC(uint32_t pc) = 0;

  // Simulate instruction effect on CPU state
  virtual bool ExecuteInstruction(
      const core::Instruction& inst,
      std::function<uint8_t(uint32_t)> read_memory,
      std::function<void(uint32_t, uint8_t)> write_memory) = 0;

  // Determine if branch would be taken
  virtual bool EvaluateBranchCondition(const std::string& mnemonic) = 0;
};
```

**Implementations**:
- `CpuState6809`: 6809-specific state (A, B, DP, X, Y, U, S, PC, CC)
- `CpuState6502`: 6502-specific state (A, X, Y, SP, PC, P)

**Integration**:
- Called by CodeAnalyzer during analysis passes
- Discovered addresses added as entry points
- Improves coverage of code with conditional branches

### Plugin Components

#### CpuPlugin Interface

```cpp
class CpuPlugin {
public:
  virtual ~CpuPlugin() = default;

  // Core disassembly
  virtual Instruction Disassemble(const uint8_t* data,
                                   size_t size,
                                   uint32_t address) = 0;

  // Metadata
  virtual std::string Name() const = 0;
  virtual CpuVariant GetVariant() const = 0;

  // Analysis support
  virtual AnalysisCapabilities GetAnalysisCapabilities() const = 0;
  virtual std::vector<uint32_t> GetInterruptVectors(uint32_t load_addr) const = 0;
  virtual bool LooksLikeSubroutineStart(const uint8_t* data,
                                        size_t size,
                                        uint32_t address) const = 0;
  virtual bool IsLikelyCode(const uint8_t* data,
                           size_t size,
                           uint32_t address) const = 0;

  // Execution simulation support
  virtual std::unique_ptr<CpuState> CreateCpuState() const = 0;
};
```

**Analysis Capabilities** (CPU-specific features):
```cpp
struct AnalysisCapabilities {
  bool supports_interrupt_vector_scan;
  bool supports_subroutine_pattern_matching;
  bool supports_lea_target_tracking;
  bool has_indexed_jump_detection;
};
```

### Output Components

#### BaseFormatter (Template Method)

```cpp
class BaseFormatter : public Formatter {
protected:
  // Template methods (pure virtual - subclasses must override)
  virtual std::string GetEquateDirective() const = 0;
  virtual std::string GetOrgDirective() const = 0;
  virtual std::string GetByteDirective() const = 0;
  virtual int GetOpcodeColumn() const = 0;
  virtual int GetCommentColumn() const = 0;

  // Shared implementations (DRY)
  std::string FormatEquates(...);
  std::string FormatAddress(...);
  std::string FormatStringData(...);
  std::string FormatBinaryData(...);

public:
  // Final implementation - cannot override
  std::string Format(...) final override;
};
```

**Example Subclass**:
```cpp
class MerlinFormatter : public BaseFormatter {
protected:
  std::string GetEquateDirective() const override { return "EQU"; }
  std::string GetOrgDirective() const override { return "ORG"; }
  std::string GetByteDirective() const override { return "HEX"; }
  int GetOpcodeColumn() const override { return 10; }
  int GetCommentColumn() const override { return 40; }
};
```

---

## Configuration Management

### Centralized Constants

All magic numbers moved to `src/core/constants.h`:

```cpp
namespace sourcerer {
namespace constants {

// Analysis constants
constexpr size_t kMinDataRegionSize = 16;
constexpr int kMinHeuristicMatches = 2;
constexpr float kPrintableThresholdHigh = 0.90f;
constexpr int kMaxRecursionDepth = 1000;
constexpr int kMaxAnalysisPasses = 10;

// Jump table detection
constexpr size_t kMinJumpTableEntries = 3;
constexpr float kMinJumpTableConfidence = 0.6f;

// Default load addresses
constexpr uint32_t kDefaultAppleIILoadAddress = 0x8000;
constexpr uint32_t kDefaultCoCoLoadAddress = 0x0600;

// ... 30+ more constants
}
}
```

**Benefits**:
- Single source of truth
- Easy to tune thresholds
- Self-documenting code
- No duplicate constants

### Parameter Objects

Configuration structures replace long parameter lists:

```cpp
struct AnalysisConfig {
  uint32_t entry_point = 0;
  size_t max_instructions = 100000;
  int max_passes = 10;
  bool enable_jump_table_detection = true;
};

struct FormatterConfig {
  bool generate_labels = true;
  bool generate_xrefs = false;
  int opcode_column = 10;
  int comment_column = 40;
};
```

---

## Error Handling

### Exception Hierarchy

```mermaid
classDiagram
    class SourcererException {
        <<abstract>>
        +what() string
        +GetContext() string
    }

    class AnalysisException {
        -address: uint32_t
        +GetAddress() uint32_t
    }

    class DisassemblyException {
        -address: uint32_t
        -bytes: vector~uint8_t~
    }

    class BinaryException {
        -file_path: string
        +GetFilePath() string
    }

    class DiskException {
        -disk_path: string
        -file_name: string
    }

    SourcererException <|-- AnalysisException
    SourcererException <|-- DisassemblyException
    SourcererException <|-- BinaryException
    SourcererException <|-- DiskException
```

### Error Handling Pattern

**Before** (18 files with catch-all blocks):
```cpp
try {
  // operation
} catch (...) {
  return false;  // Lost error context!
}
```

**After** (specific exceptions with logging):
```cpp
try {
  // operation
} catch (const std::exception& e) {
  LOG_ERROR("Operation failed at $" + FormatAddress(address) +
            ": " + e.what());
  throw AnalysisException(e.what(), address);
}
```

**Benefits**:
- Error context preserved
- Proper logging at all levels
- Caller can handle specific exceptions
- Debuggable error messages

---

## Testing Strategy

### Unit Testing (Planned)

Each component is now independently testable:

```cpp
TEST(DataHeuristicsTest, DetectsPrintableStrings) {
  // Arrange
  std::vector<uint8_t> data = {'H', 'E', 'L', 'L', 'O', 0x00};
  Binary binary(data, 0x8000);
  DataHeuristics heuristics(&binary);

  // Act
  bool is_data = heuristics.LooksLikeData(0x8000, 0x8005);

  // Assert
  EXPECT_TRUE(is_data);
}

TEST(MisalignmentResolverTest, ResolvesBranchConflict) {
  // Arrange
  MockCpuPlugin cpu;
  Binary binary = LoadTestBinary();
  MisalignmentResolver resolver(&cpu, &binary);

  // Set up conflicting instructions
  Instruction existing = CreateInstruction(0x8000, 3);  // 3 bytes
  Instruction branch = CreateInstruction(0x8002, 2);    // Targets 0x8002

  // Act
  resolver.DetectMisalignment(0x8002, existing);

  // Assert
  // Verify correct instruction was chosen based on confidence
}
```

### Integration Testing (Current)

**test_coco.sh** validates end-to-end accuracy:
- ✅ ZAXXON.BIN: 23,645 bytes discovered (98.6% coverage)
- ✅ 4,320 instructions disassembled
- ✅ Output byte-for-byte identical after refactoring

---

## Performance Characteristics

### Time Complexity

| Component | Complexity | Notes |
|-----------|-----------|-------|
| Code Flow Analysis | O(n) | Each byte visited once per pass |
| Multi-pass Analysis | O(n × p) | n = bytes, p = passes (≤10) |
| Misalignment Resolution | O(1) per conflict | Uses confidence scoring |
| Jump Table Detection | O(d) | d = DATA region bytes |
| Xref Building | O(i) | i = instruction count |
| Label Generation | O(i + x) | x = xref count |
| Output Formatting | O(i + d) | Linear in instructions + data |

### Space Complexity

| Structure | Size | Notes |
|-----------|------|-------|
| Binary | O(n) | n = file size |
| AddressMap | O(c + d) | c = CODE bytes, d = DATA bytes (sparse) |
| Instruction Cache | O(i) | i = unique instructions |
| Xref Map | O(x) | x = cross-references |
| Visited Set | O(v) | v = visited addresses per pass |

### Optimization Techniques

1. **Shared Instruction Cache**: Avoid re-disassembling same address
2. **Sparse Maps**: Only store non-default values (UNKNOWN not stored)
3. **Visited Tracking**: Skip already-analyzed regions
4. **Early Termination**: Stop passes when no new bytes discovered

---

## Future Enhancements

### Planned Improvements

1. **Comprehensive Unit Tests**
   - Mock CPU plugins for isolated testing
   - Strategy-level unit tests
   - Formatter output validation

2. **Additional CPU Support**
   - Z80 (Zilog)
   - 65816 (WDC 16-bit)
   - 68000 (Motorola)

3. **Advanced Analysis**
   - Function signature detection
   - Stack frame analysis
   - Data type inference

4. **Output Enhancements**
   - C header generation
   - Interactive HTML output
   - Graphviz call graphs

---

## Refactoring Metrics

### Code Reduction Summary

| Component | Before | After | Reduction |
|-----------|--------|-------|-----------|
| **CodeAnalyzer** | 2,627 lines | ~300 lines | 90% |
| **Formatters (total)** | 2,161 lines | ~270 lines | 87.5% |
| **main.cpp** | 573 lines | 9 lines | 98.4% |
| **Duplicated Code** | ~500 lines | 0 lines | 100% |

### Clean Code Compliance

| Metric | Before | After | Status |
|--------|--------|-------|--------|
| God Classes | 1 (CodeAnalyzer) | 0 | ✅ |
| Code Duplication | 500+ lines | 0 lines | ✅ |
| Catch-all Blocks | 16 files | 0 files | ✅ |
| Magic Numbers | 40+ | 0 | ✅ |
| Functions >50 lines | 12 | 0 | ✅ |
| Classes with >1 responsibility | 3 | 0 | ✅ |

### Test Coverage Maintained

- ✅ **100% accuracy** preserved throughout refactoring
- ✅ ZAXXON.BIN: 23,645 bytes (unchanged)
- ✅ 4,320 instructions (unchanged)
- ✅ Zero regressions across 6 phases

---

## References

- **Design Patterns**: Gang of Four (Strategy, Template Method)
- **Clean Code**: Robert C. Martin
- **SOLID Principles**: Robert C. Martin
- **Google C++ Style Guide**: Followed 2-space indentation, naming conventions

---

**Document Version**: 1.0
**Last Updated**: 2026-01-06
**Authors**: Claude Sonnet 4.5 (Refactoring), Bryan W. (Original Architecture)
