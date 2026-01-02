# Platform Configuration System

Sourcerer uses a flexible platform configuration system that allows both built-in platform support and user extensions.

## Built-in Platforms

Current platforms are defined in `symbols/platforms/`:

- **apple2** - Apple II (6502)
  - Core symbols: apple2_rom.json, apple2_zeropage.json
  - Extensions: ProDOS, DOS 3.3

## Platform Configuration Structure

Each platform is defined by a JSON file in `symbols/platforms/{platform}.platform.json`:

```json
{
  "platform": "apple2",
  "name": "Apple II",
  "cpu": "6502",
  "symbol_files": ["symbols/apple2_rom.json"],
  "hint_files": [],
  "inline_data_routines": [],
  "extensions": {
    "prodos": {
      "symbol_files": ["symbols/prodos8.json"],
      "inline_data_routines": [
        {"address": "0xBF00", "name": "MLI", "bytes_after_call": 3}
      ]
    }
  }
}
```

## User Extensions

### Method 1: User Symbol File (Recommended)

Create a file named `{platform}.user.json` in the `symbols/` directory:

**Example: `symbols/apple2.user.json`**
```json
{
  "platform": "apple2",
  "description": "My custom Apple II symbols",
  "symbols": [
    {
      "address": "0x6000",
      "name": "MY_ROUTINE",
      "description": "My game routine",
      "type": "routine"
    }
  ]
}
```

The platform loader will automatically find and load this file when `--platform apple2` is used.

### Method 2: Explicit Symbol Files

You can always specify additional symbol files explicitly:

```bash
sourcerer --platform apple2 --symbols my_game_symbols.json -i game.bin -o game.s
```

### Method 3: Custom Platform Definition

Create your own platform file in `symbols/platforms/`:

**Example: `symbols/platforms/mygame.platform.json`**
```json
{
  "platform": "mygame",
  "name": "My Game",
  "description": "Custom configuration for my Apple II game",
  "cpu": "6502",
  "base_platform": "apple2",
  "symbol_files": [
    "symbols/apple2_rom.json",
    "symbols/apple2_zeropage.json",
    "symbols/mygame_symbols.json"
  ],
  "entry_points": {
    "default": "0x4000"
  }
}
```

Then use it:
```bash
sourcerer --platform mygame -i game.bin -o game.s
```

## Symbol File Format

Symbol files use this JSON format:

```json
{
  "platform": "platform_name",
  "description": "Description of symbols",
  "version": "1.0",
  "symbols": [
    {
      "address": "0xFC58",
      "name": "HOME",
      "description": "Clear screen routine",
      "type": "routine"
    },
    {
      "address": "0x24",
      "name": "CH",
      "description": "Cursor horizontal position",
      "type": "data"
    }
  ]
}
```

### Symbol Types

- **routine** - Subroutine or function
- **data** - Data variable or buffer
- **io_port** - I/O port or hardware register
- **mli_call** - MLI/BIOS call entry point

## Hint Files

Hint files provide additional information for the analyzer:

```json
{
  "platform": "apple2_prodos",
  "description": "ProDOS hints",
  "inline_data_routines": [
    {
      "address": "0xBF00",
      "name": "MLI",
      "pattern": "JSR_BYTE_WORD",
      "bytes_after_call": 3
    }
  ],
  "mli_parameter_structures": {
    "0xC8": {
      "name": "OPEN",
      "parameters": [
        {"offset": 0, "size": 1, "name": "param_count"},
        {"offset": 1, "size": 2, "name": "pathname"}
      ]
    }
  }
}
```

## Search Paths

Sourcerer searches for platform files in:

1. `./symbols/platforms/`
2. `~/.sourcerer/platforms/` (user-specific)
3. `/usr/local/share/sourcerer/platforms/` (system-wide)

For symbol files:

1. `./symbols/`
2. `~/.sourcerer/symbols/`
3. `/usr/local/share/sourcerer/symbols/`

## Example: Disassembling a ProDOS Program

```bash
# Using platform with extensions
sourcerer --platform apple2 -i program.sys -a 0x2000 -o program.s

# With explicit ProDOS support
sourcerer --platform apple2 \
          --symbols symbols/prodos8.json \
          -i program.sys -a 0x2000 -o program.s

# With custom symbols
sourcerer --platform apple2 \
          --symbols my_program_symbols.json \
          -i program.sys -o program.s
```

## Tips

1. **Start Simple**: Use `{platform}.user.json` for your custom symbols
2. **Share Symbols**: Export your symbol files for others to use
3. **Document**: Add good descriptions to your symbols
4. **Test**: Verify symbols load with `--verbose` flag
5. **Version**: Track symbol file versions in the JSON

## Future Enhancements

Planned features:
- Platform inheritance (extend base platforms)
- Auto-detection of platform from binary headers
- Symbol database with version control
- Online symbol repository
- IDE integration for symbol editing
