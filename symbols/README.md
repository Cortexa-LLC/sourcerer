# Symbol Tables

This directory contains JSON symbol table definitions for various platforms and operating systems.

## Format

Each JSON file contains:
- `platform`: Platform identifier (e.g., "apple2e", "prodos8", "dos33")
- `description`: Human-readable description
- `version`: Symbol table version
- `source`: Reference to documentation source
- `symbols`: Array of symbol definitions

### Symbol Definition

```json
{
  "address": "0xC000",
  "name": "KEYBOARD",
  "type": "io_port",
  "description": "Read keyboard data"
}
```

**Address formats supported:**
- Hexadecimal with 0x prefix: `"0xC000"`
- Hexadecimal with $ prefix: `"$C000"`
- Decimal: `"49152"`

**Symbol types:**
- `io_port`: Memory-mapped I/O location
- `rom_routine`: ROM subroutine entry point
- `zero_page`: Zero page variable/pointer
- `system_variable`: OS/system variable
- `soft_switch`: Hardware soft switch
- `hardware`: Hardware register/status flag
- `mli_call`: OS MLI/API call number
- `unknown`: Unknown type

## Available Symbol Tables

### Apple IIe (`apple2e.json`)
Comprehensive Apple IIe memory map including:
- **Zero page variables** ($00-$FF): Window settings, cursor position, base addresses, Applesoft pointers
  - Text window (WNDLFT, WNDWDTH, WNDTOP, WNDBTM)
  - Cursor position (CH, CV)
  - Base addresses (BASL/BASH, GBASL/GBASH)
  - I/O vectors (CSWL/CSWH, KSWL/KSWH)
  - Applesoft pointers (TXTTAB, VARTAB, ARYTAB, STREND, FRETOP, PRGEND)

- **Memory management soft switches** ($C000-$C00B):
  - 80STOREON/OFF, RAMRD, RAMWRT, INTCXROM, ALTZP, SLOTC3ROM

- **Video soft switches** ($C00C-$C00F, $C050-$C057):
  - 80-column mode, alternate character set
  - Text/graphics mode, mixed mode, page switching
  - Lo-res/hi-res graphics

- **Soft switch status flags** ($C010-$C01F):
  - Keyboard, bank-switched RAM, memory configuration
  - Video mode status, vertical blanking

- **I/O ports** ($C000-$C070):
  - Keyboard (KBD, KBDSTRB)
  - Speaker (SPKR), cassette (TAPEOUT, CASSIN)
  - Game controller (PADDL0-3, PB0-2, PTRIG)

- **Annunciator switches** ($C058-$C05F):
  - CLRAN0-3, SETAN0-3

- **Bank-switched RAM controls** ($C080-$C08B):
  - READBSR1/2, WRITEBSR1/2, OFFBSR1/2, RDWRBSR1/2

- **ROM routines** ($F800-$FFFF):
  - Screen control (HOME, VTAB, CLREOP, CLREOL, CR)
  - Character I/O (COUT, COUT1, RDKEY, RDCHAR, GETLN)
  - Display (PRBYTE, PRHEX, PRINTYX, BASCALC)
  - Utility (BELL, WAIT, PREAD)
  - Monitor (MONITOR, MONZ)

**Source:** Inside the Apple IIe by Gary B. Little (1985)

### ProDOS 8 (`prodos8.json`)
ProDOS 8 Machine Language Interface:
- **MLI entry point** ($BF00): Main ProDOS API entry
- **System global page** ($BE00-$BEFF):
  - Device information (DEVNUM, DEVCNT, DEVLST)
  - Configuration (TSLOT, TDRIVE, PFIXPTR)
  - Date/time (DATELO, TIMELO)
  - File system (LEVEL, BUBIT)
  - Version information (VERSION, KVERSION)

**Source:** ProDOS 8 Technical Reference Manual

### DOS 3.3 (`dos33.json`)
DOS 3.3 Disk Operating System:
- **Page 3 vectors** ($3D0-$3DB):
  - DOS_WARM: Reconnect DOS without destroying program
  - DOS_COLD: Initialize DOS and clear memory
  - DOS_FM: File manager entry point
  - DOS_RWTS: Read/Write Track/Sector entry point

- **File buffers** ($9600-$9CFF):
  - DOS_BUF1-3: Default 595-byte file buffers
  - Configurable via MAXFILES command

- **DOS code area** ($9D00-$BFFF):
  - DOS_START/DOS_END: DOS 3.3 code boundaries

**Source:** Inside the Apple IIe by Gary B. Little (1985)

## Usage

Load symbol tables in your code:
```cpp
core::SymbolTable symbols;
symbols.LoadFromFile("symbols/apple2e.json");
symbols.LoadFromFile("symbols/prodos8.json");
// or
symbols.LoadFromFile("symbols/dos33.json");
```

Or specify via command line:
```bash
sourcerer -i program.bin -o program.s \
  --symbols symbols/apple2e.json \
  --symbols symbols/prodos8.json
```

## Symbol Table Combinations

Common combinations for different environments:

**ProDOS Environment:**
```bash
--symbols symbols/apple2e.json --symbols symbols/prodos8.json
```

**DOS 3.3 Environment:**
```bash
--symbols symbols/apple2e.json --symbols symbols/dos33.json
```

**Bare Metal / Monitor:**
```bash
--symbols symbols/apple2e.json
```

## References

- **Inside the Apple IIe** (Apple Computer, 1985) - Complete hardware reference
- **Apple IIe Technical Reference Manual** (1985) - Hardware specifications
- **ProDOS 8 Technical Reference Manual** - ProDOS MLI documentation
- **Applesoft BASIC Programming Reference Manual** - Applesoft zero page usage
- **DOS 3.3 Manual** - DOS file system and vectors

## Creating New Symbol Tables

To create symbol tables for other platforms (C64, TRS-80, CoCo, etc.):

1. Create a new JSON file following the format above
2. Include platform-specific memory addresses
3. Document the source of your symbol definitions
4. Test with actual binaries for that platform

Example for a new platform:
```json
{
  "platform": "c64",
  "description": "Commodore 64 Memory Map",
  "version": "1.0",
  "source": "Commodore 64 Programmer's Reference Guide",
  "symbols": [
    {
      "address": "0xD020",
      "name": "BORDER",
      "type": "hardware",
      "description": "Border color"
    }
  ]
}
```
