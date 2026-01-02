# Quality Enhancement Targets

This document analyzes high-quality assembly code from reference codebases to define our quality goals for disassembly output.

## Reference Codebases

1. **SCMASM SCI** - SCMASM 3.1 assembler source code (`~/Projects/Vintage/tools/scmasm/SCI/`)
   - Professional, production-quality 6502 assembly
   - SCMASM syntax conventions
   - Extensive use of local labels, comments, and structured layout

2. **Prince of Persia Source** - Jordan Mechner's game source (`~/Projects/Vintage/Apple/adamgreen-pop/`)
   - Merlin syntax conventions
   - Game development assembly patterns
   - Optimized 6502 code with data tables

## Key Quality Patterns

### 1. Local Labels for Branch Targets

**Current Output:**
```asm
SUB_8000 LDA   #$00
         BEQ   L_8005
         LDA   #$01
L_8005   RTS
```

**Target Quality (SCMASM):**
```asm
SUB_8000 LDA   #$00
         BEQ   .1
         LDA   #$01
.1       RTS
```

**Target Quality (Merlin):**
```asm
SUB_8000 LDA   #$00
         BEQ   :DONE
         LDA   #$01
:DONE    RTS
```

**Rules:**
- Local labels for branch targets **within** the same subroutine
- SCMASM: Use `.N` notation (`.1`, `.2`, `.3`, etc.)
- Merlin: Use `:NAME` notation (`:LOOP`, `:DONE`, `:SKIP`, etc.)
- Reset local label counter at each subroutine boundary
- Use full labels (L_xxxx) only for branches across subroutines

**Example from SC.LOAD.SAVE.s:**
```asm
DASH
       LDA GET.SET.PARMS+4      GET FILE TYPE
       CMP #$06          BINARY?
       BEQ .3            ...YES, BRUN
       CMP #$04          TEXT?
       BNE .1            ...NO, TRY SYS
       JMP EXEC          ...YES, EXEC
*--------------------------------
.1     CMP #$FF          SYS FILE?
       BEQ .2            ...YES, BRUN IT
       LDA #$0D     "FILE TYPE MISMATCH"
       SEC
       RTS
*--------------------------------
.2     JSR CLOSE.ALL.FILES
       ; ... more code ...
.3     JMP BRUN
```

### 2. Section Separators

**Current Output:**
```asm
SUB_8000 LDA   #$00
         RTS
SUB_8003 LDX   #$08
         RTS
```

**Target Quality:**
```asm
*--------------------------------
SUB_8000 LDA   #$00
         RTS
*--------------------------------
SUB_8003 LDX   #$08
         RTS
*--------------------------------
```

**Rules:**
- Add separator comment before each subroutine/major label
- SCMASM: `*--------------------------------` (32 dashes)
- Merlin: `*---------------------------------------` (38 dashes)
- Optional: Descriptive comment above separator for major routines

**Example from SC.EXEC.s:**
```asm
*--------------------------------
*   CLOSE EXEC FILE
*--------------------------------
CLOSE.EXEC.FILE
       CLC
       LDA F.EXEC
       BPL .1       ...NO EXEC IN PROGRESS
       ; ... code ...
.1     RTS
*--------------------------------
*   "EXEC" INPUT HOOK
*--------------------------------
READ.EXEC.FILE
       STA (BASL),Y      STOP BLINKING ON SCREEN
       ; ... code ...
```

### 3. Inline Comments for Branch Logic

**Current Output:**
```asm
       BEQ   .1
       BCS   .2
```

**Target Quality:**
```asm
       BEQ   .1       ...FILE EXISTS
       BCS   .2       ...ERROR
```

**Rules:**
- Add contextual comments to conditional branches
- Format: `; ...DESCRIPTION` or `...DESCRIPTION` (three dots convention)
- Describe the **condition** (what state causes the branch)
- Common patterns:
  - `...YES` / `...NO` - boolean conditions
  - `...ERROR` - error handling
  - `...NOT FOUND` - search/lookup failures
  - `...DONE` / `...COMPLETE` - completion states
  - `...ALREADY OPEN` - state checks

**Example from SC.OPEN.CLOSE.s:**
```asm
OPEN
       PHP
       JSR GET.REFNUM.OF.OPEN.FILE
       BCC .9       ...ALREADY OPEN, ERROR
       PLP          ...GET SAVED STATUS
       BCC .3       ...FILE ALREADY EXISTS
       ; ... more code ...
.9     PLP
       JMP ERR.FILE.BUSY
```

### 4. Named Constants and Equates

**Current Output:**
```asm
       LDA   #$08
       JSR   $BF00
       .HS   C8
```

**Target Quality:**
```asm
MLI.OPEN .EQ $C8

       LDA   #$08
       JSR   GP.MLI
       .HS   MLI.OPEN
```

**Rules:**
- Generate equates for:
  - Immediate values used 3+ times
  - MLI call codes ($C0-$D1)
  - Common hardware addresses
  - Zero page locations
- Place equate section at top of file
- Use descriptive names based on usage context

**Example from SC.EQUATES.s:**
```asm
*--------------------------------
GP.MLI      .EQ $BF00
UNIT        .EQ $BF30
BITMAP      .EQ $BF58
*--------------------------------
KEYBOARD .EQ $C000
STROBE   .EQ $C010
IO.OFF   .EQ $CFFF
*--------------------------------
BELL       .EQ $FBE2
COUT       .EQ $FDED
```

### 5. Jump Tables and Entry Point Patterns

**Current Output:**
```asm
SUB_8000 LDA   #$00
         JMP   L_8010
SUB_8003 LDA   #$01
         JMP   L_8010
```

**Target Quality:**
```asm
MLI.C0 LDA #$00     CREATE
       .HS 2C
DELETE
MLI.C1 LDA #$01     DESTROY
       .HS 2C
MLI.C2 LDA #$02     RENAME
       .HS 2C
       ; ... more entries ...
       ORA #$C0     MAKE INTO MLI CALL CODE
       JMP MLI.CALLER
```

**Rules:**
- Detect BIT absolute ($2C) skip pattern
- Recognize multiple entry points to same code
- Label each entry point
- Add inline comments describing entry point purpose

**Example from SC.OPEN.CLOSE.s:**
```asm
*--------------------------------
*      FOLLOWING USE "BIT" TO SKIP OVER TWO BYTES,
*      SO CANNOT HAVE THE SECOND OF THE TWO =$CX.
*--------------------------------
MLI.C0 LDA #$00     CREATE
       .HS 2C
DELETE
MLI.C1 LDA #$01     DESTROY
       .HS 2C
MLI.C2 LDA #$02     RENAME
       .HS 2C
MLI.C3 LDA #$03     SET FILE INFO
       .HS 2C
MLI.C4 LDA #$04     GET FILE INFO
       .HS 2C
```

### 6. Data Tables

**Current Output:**
```asm
       HEX   00802010803020
```

**Target Quality:**
```asm
JUMP.TABLE
       .DA ROUTINE1    ; $8000
       .DA ROUTINE2    ; $8010
       .DA ROUTINE3    ; $8020
```

**Rules:**
- Detect sequences of 16-bit values (little-endian)
- Check if values are valid code/data addresses
- Format as `.DA` (SCMASM) or `DA` (Merlin)
- Add inline comments with hex values
- Label the table

**Detection Heuristics:**
- Minimum 2 consecutive 16-bit values
- Values should be in valid address range
- Values should point to code or data regions
- Aligned on even boundaries (preferred)

### 7. String Detection

**Current Output:**
```asm
       HEX   0D46494C45204E4F5420464F554E44
```

**Target Quality:**
```asm
       .AS -"FILE NOT FOUND"
```

or for high-bit terminated:
```asm
       .AS >"FILE NOT FOUND"
```

**Rules:**
- Minimum 4 printable characters
- Check for:
  - Length-prefixed strings
  - Zero-terminated strings
  - High-bit terminated strings (Apple II convention)
  - Negative ASCII (high bit set on all chars)
- Use appropriate directive:
  - `.AS "..."` - normal ASCII (SCMASM)
  - `.AS -"..."` - inverse/flashing (SCMASM)
  - `.AS >"..."` - high-bit set (SCMASM)
  - `ASC "..."` - normal (Merlin)
  - `DCI "..."` - high-bit terminated (Merlin)

### 8. Zero Page Usage Comments

**Current Output:**
```asm
       LDA   $10
       STA   $11
```

**Target Quality:**
```asm
       LDA   COUNTER       ; $10
       STA   POINTER       ; $11
```

**Rules:**
- Use symbol table names for known zero page locations
- Add hex address in comment for clarity
- Common Apple II zero page locations should have standard names

### 9. Loop Counter Comments

**Current Output:**
```asm
       LDX   #$08
:LOOP  DEX
       BNE   :LOOP
```

**Target Quality:**
```asm
       LDX   #$08        ; Loop 8 times
:LOOP  DEX
       BNE   :LOOP
```

**Rules:**
- Detect immediate loads followed by loop patterns
- Add comment indicating loop count
- Common pattern: LDX/LDY immediate → loop with DEX/DEY → BNE

### 10. Common Operation Comments

**Target Quality:**
```asm
       LDA   #$00        ; Clear accumulator
       STA   $10         ; Initialize counter
       CLC               ; Clear carry for addition
       ADC   #$01        ; Increment
       BMI   .1          ; Branch if negative
```

**Rules:**
- Add comments for obvious operations (helps readability)
- Only for truly common idioms
- Don't over-comment obvious code

## Implementation Priority

1. **Local Labels** - Highest impact on readability
2. **Section Separators** - Easy to implement, big visual improvement
3. **Inline Branch Comments** - Helps understand control flow
4. **16-bit Value Detection** - Critical for address tables
5. **String Detection Improvements** - Better data formatting
6. **Equate Generation** - Reduces magic numbers
7. **Common Pattern Comments** - Polish/final touches

## Test Cases

Each enhancement should be tested with:
- Small synthetic examples
- Real code from SCMASM SCI
- Real code from Prince of Persia
- Round-trip assembly validation

## Success Criteria

Output should:
1. Use local labels within subroutines (no L_xxxx for local branches)
2. Have clear visual separation between routines
3. Include helpful inline comments for branches
4. Format data tables as `.DA` / `DA` when appropriate
5. Detect and format strings properly
6. Generate equates for repeated values
7. Be assembly-compatible (round-trip test)
8. Be as readable as hand-written professional code

## Example: Before and After

### Before (Current)
```asm
*---------------------------------------
* Disassembly of: example.bin
*---------------------------------------
         ORG   $8000

L_8000   LDA   #$00
         BEQ   L_8005
         LDA   #$01
L_8005   STA   $10
         JSR   L_8010
         RTS
L_8010   LDX   #$08
L_8012   DEX
         BNE   L_8012
         RTS
         HEX   0080

         CHK
```

### After (Target Quality)
```asm
*---------------------------------------
* Disassembly of: example.bin
*---------------------------------------
COUNTER  .EQ $10

         .OR   $8000
*--------------------------------
MAIN     LDA   #$00        ; Clear accumulator
         BEQ   .1          ...SKIP ALTERNATE VALUE
         LDA   #$01
.1       STA   COUNTER     ; Initialize counter
         JSR   DELAY
         RTS
*--------------------------------
DELAY    LDX   #$08        ; Loop 8 times
.1       DEX
         BNE   .1
         RTS
*--------------------------------
JUMP.TABLE
         .DA MAIN          ; $8000
*--------------------------------

         .TF
```

## Notes

- Local label implementation requires tracking subroutine boundaries
- Branch target analysis must distinguish local vs. non-local
- Some patterns require multi-pass analysis
- Balance automation with accuracy (don't over-comment obvious code)
- Platform-specific patterns (MLI calls, ROM routines) need special handling
