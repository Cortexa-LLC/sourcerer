# Test Sample Binaries

This directory contains test binaries for integration testing.

## Directory Structure

```
samples/
├── apple2/         # Apple II (6502/65C02) test binaries
│   ├── GRAFIX.bin  # Graphics data (2.5KB)
│   └── GAMEBG.bin  # Game background (1.5KB)
├── coco/           # CoCo (6809) test binaries
│   └── ZAXXON.DSK  # ZAXXON arcade game disk (obtain separately)
└── model3/         # TRS-80 Model III (Z80) test binaries
    └── (future)
```

## Setup

Run the setup script to configure your test environment:

```bash
python setup.py
```

This will:
- Check for required tools (cmake, compiler)
- Check/install cocofs (for CoCo disk extraction)
- Guide you through obtaining test files
- Create .env configuration

## CoCo Samples (6809)

### ZAXXON.DSK

**Source**: Must be obtained legally from:
- [Color Computer Archive](https://colorcomputerarchive.com)
- Original disk if you own it
- Other legal sources

**Details**:
- Game: ZAXXON (Datasoft)
- Binary: ZAXXON.BIN (16,646 bytes)
- Load address: $4101
- Used for: Integration testing (98.6% code coverage validation)

**Installation**:
1. Obtain ZAXXON.DSK legally
2. Place in `samples/coco/ZAXXON.DSK`
3. Or set `ZAXXON_DISK_PATH` environment variable

## Apple II Samples (6502)

### GRAFIX.bin
- Graphics data routine
- Size: 2.5KB
- Included in repository

### GAMEBG.bin
- Game background data
- Size: 1.5KB
- Included in repository

## TRS-80 Model III Samples (Z80)

Z80 CPU support not yet implemented. Test samples will be added when ready.

## Required Tools

### cocofs (CoCo disk extractor)

**macOS (Homebrew)**:
```bash
brew tap stahta01/coco
brew install cocofs
```

**Linux (from source)**:
```bash
git clone https://github.com/stahta01/cmoc-win32.git
# Build cocofs from source
```

**Windows**: Use WSL or build from source

## Environment Variables

Set in `.env` file or shell:

```bash
# CoCo tests
export ZAXXON_DISK_PATH="samples/coco/ZAXXON.DSK"
export COCOFS_PATH="/usr/local/bin/cocofs"
```

## Running Tests

```bash
# All platforms
python test.py

# Specific platform
python test.py coco      # Requires ZAXXON.DSK and cocofs
python test.py apple2    # Uses included binaries
python test.py trs80     # Not yet implemented
```

## Legal Notice

Test binaries should be obtained legally:
- Use original media you own
- Download from authorized archives
- Respect copyright and distribution terms

This project does not distribute copyrighted binaries without permission.
