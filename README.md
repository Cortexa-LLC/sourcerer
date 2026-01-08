# Sourcerer - Modern Multi-CPU Disassembler

A modern C++ command-line disassembler inspired by Merlin Pro's SOURCEROR, designed with a modular plugin architecture to support multiple CPU types and output formats. Produces high-quality, re-assemblable source code with intelligent analysis and platform-specific symbol support.

## Key Features

### Intelligent Analysis
- **Code Flow Analysis**: Multi-pass analysis follows branches, JSR/RTS, and control flow
- **Dynamic Execution Simulation**: Evaluates branch conditions to discover conditional code paths
- **Data Detection**: Distinguishes strings, address tables, and binary data
- **Smart Label Generation**: Context-aware labels (SUB_xxxx, L_xxxx, DATA_xxxx)
- **Cross-References**: Track and comment where addresses are referenced
- **Inline Data Detection**: Handles ProDOS MLI and other inline parameter patterns

### Platform Support
- **Symbol Libraries**: Built-in Apple II ROM, zero page, ProDOS symbols
- **User Extensions**: Easy to add custom symbols via `.user.json` files
- **Platform Configurations**: Extensible platform definition system
- **Auto-Loading**: Symbols automatically load with `--platform apple2`

### Output Quality
- **EQU Statements**: Platform symbols output as EQU definitions
- **Symbol Substitution**: Addresses replaced with names (COUT, HOME, MLI)
- **Address Tables**: DA directives with symbol names instead of raw addresses
- **Aligned Comments**: Consistent comment column alignment
- **Clean Formatting**: Follows Merlin/SCMASM conventions

### Multi-CPU & Format Support
- **CPUs**: 6502, 65C02, 6809 with full execution simulation support (65816, Z80 coming soon)
- **Output Formats**: Merlin, SCMASM 3.1, EDTASM+
- **Disk Images**: Apple DOS 3.3, ProDOS, CoCo DSK via native extractors
- **Modern CLI**: Intuitive command-line with `--platform`, `--symbols`, `--hints`

## Building

### Requirements

- C++17 compatible compiler (GCC 7+, Clang 5+, MSVC 2017+)
- CMake 3.15 or higher
- Java JRE (for ACX.jar disk extraction)
- Python 3.6+ (for setup script)

### Build Instructions

```bash
# 1. Install dependencies (ACX.jar)
python3 setup.py

# 2. Build using Makefile (recommended)
make build

# Or using CMake directly
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build

# 3. Install (optional)
cd build && sudo make install

# The executable will be in build/sourcerer (or /usr/local/bin after install)
```

**Makefile Targets:**
- `make build` - Build project
- `make test` - Build and run all tests
- `make coverage` - Build with coverage and run tests
- `make clean` - Clean build artifacts
- `make help` - Show all available targets

**Windows users:** Replace `make` with `cmake --build . --config Release`

### Run Tests

The project includes comprehensive test coverage with **689 tests** achieving **80.5% code coverage**:
- Core modules: 95 tests (92.4% coverage)
- CPU plugins (6502/65C02/6809): 162 tests (80.6% coverage)
- Analysis modules: 329 tests (75.8% coverage)
- Output formatters: 103 tests (79.8% coverage)

```bash
# Using Makefile (recommended)
make test           # Build and run all tests
make coverage       # Build with coverage and run tests

# Or using CMake directly
cmake -B build -DBUILD_TESTING=ON
cmake --build build
cd build && ctest --output-on-failure

# Run specific test suites
./build/tests/test_core
./build/tests/test_6502
./build/tests/test_analysis
./build/tests/test_formatters
```

## Usage

### Quick Start

```bash
# Disassemble with Apple II platform symbols (auto-loads ROM, zero page)
./sourcerer --platform apple2 -i program.bin -a 0x8000 -o program.s

# Extract from ProDOS disk
./sourcerer --platform apple2 -d disk.dsk --file PROGRAM.SYS -o program.s

# Add your custom symbols
./sourcerer --platform apple2 --symbols my_game_symbols.json -i game.bin -o game.s
```

### Example Output

Input: Simple Apple II program
```asm
         JSR   $FDED
         JSR   $FC58
         STA   $33
         RTS
```

Output with platform symbols:
```asm
HOME     EQU   $FC58
COUT     EQU   $FDED

         ORG   $8000

         JSR   COUT
         JSR   HOME
         STA   PROMPT
         RTS

         CHK
```

### Advanced Examples

```bash
# ProDOS program with verbose output
./sourcerer --platform apple2 --symbols symbols/prodos8.json \
            -i program.sys -a 0x2000 -o program.s --verbose

# Disk operations
./sourcerer --list-files mydisk.dsk                    # List files
./sourcerer -d mydisk.dsk --file HELLO -o hello.s   # Extract & disassemble

# With hints and cross-references
./sourcerer -i program.bin -a 0x8000 \
            --hints program.hints.json --xref -o program.s

# Different output format (SCMASM 3.1)
./sourcerer -c 65c02 --platform apple2 \
            -i program.bin -a 0x8000 -f scmasm -o program.s

# Linear disassembly (no analysis)
./sourcerer -i program.bin -a 0x8000 --no-analysis -o program.s
```

### Command-Line Options

```
sourcerer [OPTIONS] -i INPUT -o OUTPUT

Required:
  -i, --input FILE           Input file (disk image or binary)
  -o, --output FILE          Output assembly file

CPU Options:
  -c, --cpu TYPE             CPU type: 6502, 65c02 (default: 6502)

Platform Options:
  -p, --platform NAME        Platform (e.g., apple2) - auto-loads symbols
  --symbols FILE             Additional symbol file(s) (can specify multiple)

Disk Options:
  -d, --disk                 Input is a disk image
  --file NAME                File to extract from disk
  --list-files               List files in disk image and exit

Address Options:
  -a, --address ADDR         Load address for raw binary (hex)
  --entry ADDR               Entry point address (default: load address)

Analysis Options:
  --hints FILE               Hints file (JSON)
  --no-analysis              Disable code flow analysis (linear only)
  --xref                     Generate cross-references

Output Options:
  -f, --format TYPE          Output format: merlin, scmasm (default: merlin)
  --no-labels                Don't generate labels
  -v, --verbose              Verbose output
```

## Architecture

### Formatter Design: Composition Pattern

Sourcerer formatters use a **composition pattern** with three high-cohesion components:

- **DataCollector**: Collects data from binary (string detection, data collection)
- **AddressAnalyzer**: Analyzes addresses (referenced addresses, address tables)
- **LabelResolver**: Resolves labels and symbols (label substitution, symbol lookup)

Each formatter (Merlin, SCMASM, EDTASM) composes these components and adds format-specific syntax. This provides high cohesion, testability, and maintainability while avoiding the "helper" anti-pattern.

### Symbol System: Dual Name/Symbol Support

The symbol system supports dual `name`/`symbol` fields to preserve historical accuracy while ensuring assembler compatibility:

- **name**: Official documentation name (e.g., "80STOREOFF" from Apple docs)
- **symbol**: Assembler-safe identifier (e.g., "STORE80OFF" - valid in Merlin)
- Backwards compatible: `symbol` defaults to `name` if not specified

This allows Apple II symbols to maintain historical accuracy while generating valid assembly code.

### Plugin Architecture

Sourcerer uses a clean plugin architecture:

- **CPU Plugins**: Handle instruction decoding (m6502, m6809, z80)
- **Disk Extractors**: Handle disk image formats (ACX.jar, raw files)
- **Output Formatters**: Handle assembly syntax (Merlin, SCMASM, etc.)
- **Analysis Modules**: Code flow, labels, cross-references, hints

See `docs/ARCHITECTURE.md` for complete details.

## Adding New CPUs

See `docs/ADDING_CPU.md` for a guide on adding new CPU support.

## Adding Output Formats

See `docs/OUTPUT_FORMATS.md` for a guide on adding new assembly syntax formats.

## Platform Configuration

Sourcerer includes a flexible platform configuration system that supports built-in platforms and user extensions. The `--platform` option automatically loads platform-specific symbols, hints, and configurations.

See `symbols/PLATFORMS.md` for complete documentation on:
- Built-in platform definitions
- Creating user symbol files (`{platform}.user.json`)
- Custom platform configurations
- Symbol file format
- Platform extensions (ProDOS, DOS 3.3)

## CPU and Dialect Matrix

| CPU Family | Variants | Output Dialects |
|------------|----------|-----------------|
| **6502** | 6502, 65C02, 65816* | Merlin, SCMASM |
| **6809*** | 6809, 6809E | EDTASM+ |
| **Z80*** | Z80, Z80A | Z80ASM |

\* Coming soon

## License

See LICENSE file for details.

## Credits

- Inspired by SOURCEROR from Merlin Pro (Roger Wagner Publishing) and [Computerware's Sourcerer](https://colorcomputerarchive.com/repo/Documents/Manuals/Programming/Sourcerer,%20The%20(Computerware).txt)
- Uses [ACX](https://github.com/AppleCommander/acx) for disk image extraction
- Uses [CLI11](https://github.com/CLIUtils/CLI11) for command-line parsing
- Uses [nlohmann/json](https://github.com/nlohmann/json) for JSON parsing
- Uses [Google Test](https://github.com/google/googletest) for testing

## Contributing

Contributions welcome! Please ensure:
- Code follows Google C++ Style Guide
- All tests pass
- New features include tests
- Documentation is updated
