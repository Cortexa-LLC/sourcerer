# Integration Tests

Platform-independent integration tests for Sourcerer.

## Running Tests

From the project root:

```bash
# Run all platform tests
python test.py

# Run specific platform tests
python test.py coco      # CoCo (6809)
python test.py apple2    # Apple II (6502)
python test.py model3    # TRS-80 Model III (Z80)
```

Or run tests directly:

```bash
# Full integration suite
python tests/integration/test_integration.py

# Individual platforms
python tests/integration/test_coco.py
python tests/integration/test_apple2.py
python tests/integration/test_model3.py
```

## Test Coverage

### CoCo (Motorola 6809)
- **Binary**: ZAXXON.BIN (arcade game, 16,646 bytes)
- **Expected Coverage**: 98.6% (23,645 bytes discovered)
- **Expected Instructions**: 4,320
- **Format**: EDTASM+
- **Source**: Disk image extraction via `cocofs`

### Apple II (MOS 6502)
- **Binaries**:
  - GRAFIX.bin (2.5KB graphics data)
  - GAMEBG.bin (1.5KB game background)
- **Formats**: Merlin, SCMASM
- **Source**: Direct binary files

### TRS-80 Model III (Z80)
- **Status**: Not yet implemented
- **Planned**: .CMD file disassembly
- **Format**: EDTASM+

## Test Requirements

### CoCo Tests
- `cocofs` tool must be installed (in PATH or specify via `COCOFS_PATH`)
- ZAXXON.DSK test file (specify location via `ZAXXON_DISK_PATH`)

**Configuration**: Set environment variables or copy `.env.example` to `.env`:
```bash
export ZAXXON_DISK_PATH="$HOME/Downloads/Zaxxon (Datasoft)/ZAXXON.DSK"
export COCOFS_PATH="/usr/local/bin/cocofs"
```

If ZAXXON.DSK or cocofs are not found, CoCo tests will be skipped (not failed).

### Apple II Tests
- Sample binaries at `samples/apple2/`

### All Tests
- Built `sourcerer` executable at `build/sourcerer`
- Python 3.6+

## Test Output

All test output is written to `test_output/` in the project root.

## Adding New Tests

1. Create a new test script in `tests/integration/test_<platform>.py`
2. Follow the pattern in existing tests:
   - Use `Colors` class for formatted output
   - Return 0 for success, non-zero for failure
   - Create output in `test_output/` directory
3. Add platform to `test_integration.py`
4. Update this README

## Continuous Integration

For CI/CD pipelines:

```bash
# Exit code 0 = all tests passed
python test.py
```

The integration test suite will:
1. Build the project (`cmake --build build`)
2. Run all platform tests
3. Report summary with pass/fail counts
4. Exit with code 0 (success) or 1 (failure)
