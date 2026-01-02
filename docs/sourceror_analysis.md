# SOURCEROR Analysis

## Overview

SOURCEROR is a 6502 disassembler included with Merlin Pro 2.33, designed to generate assembly source code from machine code binaries on Apple II systems.

## Binary Information

**File:** `examples/sourceror.bin`
- **Source:** Extracted from SOURCEROR/OBJ on Merlin Pro 2.33 (ProDOS) side A disk
- **Type:** ProDOS BIN file
- **Size:** 4,085 bytes
- **Load Address:** $9A00
- **Format:** 6502 machine code

## File Header Analysis

First 16 bytes:
```
00000000  68 aa 68 8d 09 c0 2c 79  be 50 03 8d 08 c0 48 8a  |h.h...,y.P....H.|
00000010  48 a9 4c 8d f5 03 a9 36  8d f6 03 a9 a0 8d f7 03  |H.L....6........|
```

Initial instructions:
```
9A00: 68        PLA           ; Pull accumulator
9A01: AA        TAX           ; Transfer A to X
9A02: 68        PLA           ; Pull accumulator again
9A03: 8D 09 C0  STA $C009     ; Store to hardware register
9A06: 2C 79 BE  BIT $BE79     ; Bit test
9A09: 50 03     BVC $9A0E     ; Branch if overflow clear
9A0B: 8D 08 C0  STA $C008     ; Store to hardware register
9A0E: 48        PHA           ; Push accumulator
9A0F: 8A        TXA           ; Transfer X to A
9A10: 48        PHA           ; Push accumulator
```

## Key Observations

1. **Entry Point:** Starts at $9A00 with stack operations
2. **Hardware Access:** Immediate access to $C000 range (Apple II I/O)
3. **ProDOS Integration:** Uses standard ProDOS addresses
4. **Size:** ~4KB suggests a focused, compact implementation

## Features to Study

Based on Merlin Pro documentation and common disassembler patterns:

1. **Code Flow Analysis**
   - Tracks branches (BCC, BCS, BEQ, BNE, etc.)
   - Follows JSR calls to identify subroutines
   - Detects RTS/RTI/JMP to stop analysis paths

2. **Label Generation**
   - Creates labels for branch targets
   - Creates subroutine labels for JSR targets
   - May use hints or user input for custom labels

3. **Data Detection**
   - Identifies data embedded in code
   - May use heuristics or user hints

4. **Output Format**
   - Merlin syntax (no dot prefixes)
   - Proper column alignment
   - Comments and cross-references

## Next Steps

1. ✅ Extract binary from disk
2. ⏳ Disassemble SOURCEROR using existing tools (or manual analysis)
3. ⏳ Study algorithm by examining the code
4. ⏳ Create test cases by running SOURCEROR on known binaries
5. ⏳ Document the hints system (if any)

## Test Binaries

To validate our implementation against SOURCEROR, we should:
1. Create simple test programs (loops, branches, subroutines)
2. Run them through SOURCEROR to get reference output
3. Compare our disassembler output to SOURCEROR's
4. Verify that both can be reassembled to identical binaries

## Algorithm Hypotheses

Based on typical disassembler design, SOURCEROR likely:

### Phase 1: Initial Scan
- Load binary at specified address
- Mark entry point as CODE

### Phase 2: Code Flow Analysis
- Maintain queue of addresses to analyze
- For each address:
  - Disassemble instruction
  - Mark bytes as CODE in address map
  - If branch/jump: add target to queue
  - If JSR: add target to queue (subroutine)
  - If terminal (RTS/RTI/JMP indirect): stop path
  - Continue to next instruction

### Phase 3: Data Detection
- Any bytes not marked as CODE = DATA
- May try to detect string patterns
- May detect data tables

### Phase 4: Label Generation
- Entry point: specific name or "START"
- Subroutines: "SUBxxxx" or similar
- Branch targets: "Lxxxx" or similar
- Zero page: "ZPxx" or similar
- May allow user-defined labels via hints

### Phase 5: Output Generation
- Header comment with program info
- ORG directive for load address
- For each CODE region: format instructions with labels
- For each DATA region: format as DFB/DA directives
- Footer with CHK directive

## References

- Merlin Pro 2.33 User Manual (PDF - too large to process directly)
- Apple II Reference Manual for hardware addresses
- 6502 Programming Manual for instruction set

## Implementation Notes for Our Disassembler

Based on this analysis, our modern disassembler should:

1. **Improve on SOURCEROR:**
   - Support multiple output formats (Merlin, SCMASM, ca65)
   - Support multiple CPUs (6502, 65C02, 6809, Z80)
   - Better cross-reference generation
   - More flexible hints system (JSON)
   - Command-line interface with modern options

2. **Match SOURCEROR's strengths:**
   - Code flow analysis algorithm
   - Smart label generation
   - Clean, readable output
   - ProDOS integration (via ACX.jar for us)

3. **Testing strategy:**
   - Run SOURCEROR on test binaries
   - Compare our output to SOURCEROR's
   - Verify assembly round-trip (disassemble → assemble → binary match)
