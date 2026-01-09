#!/usr/bin/env python3
"""
Round-trip validation test for Sourcerer disassembler.

Tests: Binary → Disassemble → Reassemble → Binary comparison

Validates that disassembled source code can be reassembled to produce
an identical (or functionally equivalent) binary.
"""

import argparse
import hashlib
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple


@dataclass
class TestConfig:
    """Configuration for a round-trip test."""
    name: str
    binary_path: str
    cpu: str
    format: str
    assembler: str
    assembler_args: list[str]


# Test configurations
TEST_CONFIGS = [
    TestConfig(
        name="ZAXXON (6809)",
        binary_path="samples/6809/ZAXXON.BIN",
        cpu="6809",
        format="edtasm",
        assembler="vasm6809_edtasm",
        assembler_args=["-Fbin", "-coco-ml", "-quiet"]
    ),
    TestConfig(
        name="GRAFIX (6502)",
        binary_path="samples/6502/GRAFIX.bin",
        cpu="6502",
        format="merlin",
        assembler="vasm6502_merlin",
        assembler_args=["-Fbin", "-quiet"]
    ),
    TestConfig(
        name="GAMEBG (6502)",
        binary_path="samples/6502/GAMEBG.bin",
        cpu="6502",
        format="merlin",
        assembler="vasm6502_merlin",
        assembler_args=["-Fbin", "-quiet"]
    ),
]


class Colors:
    """ANSI color codes for terminal output."""
    GREEN = '\033[0;32m'
    RED = '\033[0;31m'
    BLUE = '\033[0;34m'
    YELLOW = '\033[1;33m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

    @classmethod
    def disable(cls):
        """Disable colors for non-TTY output."""
        cls.GREEN = cls.RED = cls.BLUE = cls.YELLOW = cls.BOLD = cls.RESET = ''


def compute_md5(file_path: Path) -> str:
    """Compute MD5 hash of a file."""
    md5 = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            md5.update(chunk)
    return md5.hexdigest()


def check_tool(tool: str) -> bool:
    """Check if a tool is available in PATH."""
    try:
        subprocess.run([tool, '--version'],
                      stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL,
                      check=False)
        return True
    except FileNotFoundError:
        return False


def disassemble(config: TestConfig, output_dir: Path) -> Tuple[bool, Path]:
    """
    Disassemble binary to source code.

    Returns:
        (success, output_path)
    """
    sourcerer = Path("build/sourcerer")
    if not sourcerer.exists():
        print(f"{Colors.RED}✗ Sourcerer not built: {sourcerer}{Colors.RESET}")
        return False, Path()

    binary_path = Path(config.binary_path)
    if not binary_path.exists():
        print(f"{Colors.RED}✗ Binary not found: {binary_path}{Colors.RESET}")
        return False, Path()

    output_asm = output_dir / f"{binary_path.stem}.asm"

    cmd = [
        str(sourcerer),
        "--cpu", config.cpu,
        "--format", config.format,
        "--input", str(binary_path),
        "--output", str(output_asm)
    ]

    print(f"  Command: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        if result.stdout:
            print(f"  {result.stdout}")

        if not output_asm.exists():
            print(f"{Colors.RED}✗ Disassembly output not created{Colors.RESET}")
            return False, Path()

        line_count = len(output_asm.read_text().splitlines())
        print(f"{Colors.GREEN}✓ Disassembly successful{Colors.RESET}")
        print(f"  Output: {output_asm} ({line_count:,} lines)")

        return True, output_asm

    except subprocess.CalledProcessError as e:
        print(f"{Colors.RED}✗ Disassembly failed{Colors.RESET}")
        if e.stderr:
            print(f"  Error: {e.stderr}")
        return False, Path()


def reassemble(config: TestConfig, asm_path: Path, output_dir: Path) -> Tuple[bool, Path]:
    """
    Reassemble source code to binary.

    Returns:
        (success, output_path)
    """
    if not check_tool(config.assembler):
        print(f"{Colors.YELLOW}⚠ Assembler not found: {config.assembler}{Colors.RESET}")
        print(f"  Install with: brew install vasm")
        print(f"  Or download from: http://sun.hasenbraten.de/vasm/")
        return False, Path()

    output_bin = output_dir / f"{asm_path.stem}_reassembled.bin"
    log_file = output_dir / "assembly.log"

    cmd = [config.assembler] + config.assembler_args + ["-o", str(output_bin), str(asm_path)]

    print(f"  Command: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)

        # Save log
        with open(log_file, 'w') as f:
            f.write(result.stdout)
            f.write(result.stderr)

        if result.stdout and '--verbose' in sys.argv:
            print(f"  {result.stdout}")

        if not output_bin.exists():
            print(f"{Colors.RED}✗ Reassembled binary not created{Colors.RESET}")
            print(f"  Check log: {log_file}")
            return False, Path()

        print(f"{Colors.GREEN}✓ Reassembly successful{Colors.RESET}")

        return True, output_bin

    except subprocess.CalledProcessError as e:
        print(f"{Colors.RED}✗ Reassembly failed{Colors.RESET}")
        if e.stderr:
            print(f"  Error: {e.stderr}")
        print(f"  Check log: {log_file}")
        return False, Path()


def compare_binaries(original: Path, reassembled: Path, max_acceptable_diff: int = 10) -> bool:
    """
    Compare two binaries byte-by-byte.

    Args:
        original: Original binary path
        reassembled: Reassembled binary path
        max_acceptable_diff: Maximum number of differing bytes to consider acceptable

    Returns:
        True if binaries match (or differences are acceptable)
    """
    original_size = original.stat().st_size
    reassembled_size = reassembled.stat().st_size

    original_md5 = compute_md5(original)
    reassembled_md5 = compute_md5(reassembled)

    print(f"\nOriginal binary:")
    print(f"  Size: {original_size:,} bytes")
    print(f"  MD5:  {original_md5}")

    print(f"\nReassembled binary:")
    print(f"  Size: {reassembled_size:,} bytes")
    print(f"  MD5:  {reassembled_md5}")
    print()

    # Check size
    if original_size != reassembled_size:
        print(f"{Colors.RED}✗ FAILED: Size mismatch{Colors.RESET}")
        print(f"  Original:    {original_size:,} bytes")
        print(f"  Reassembled: {reassembled_size:,} bytes")
        print(f"  Difference:  {reassembled_size - original_size:+,} bytes")
        return False

    # Check MD5
    if original_md5 == reassembled_md5:
        print(f"{Colors.GREEN}✓ PERFECT MATCH: Binaries are identical!{Colors.RESET}")
        return True

    # Byte-by-byte comparison
    print(f"{Colors.YELLOW}⚠ WARNING: MD5 checksum mismatch{Colors.RESET}")
    print(f"  Original:    {original_md5}")
    print(f"  Reassembled: {reassembled_md5}")
    print()
    print("Performing byte-by-byte comparison...")

    with open(original, 'rb') as f1, open(reassembled, 'rb') as f2:
        differences = []
        pos = 0

        while True:
            b1 = f1.read(1)
            b2 = f2.read(1)

            if not b1 or not b2:
                break

            if b1 != b2:
                differences.append((pos, b1[0], b2[0]))

            pos += 1

    # Show first differences
    print(f"\nFirst {min(20, len(differences))} differences:")
    for pos, orig, reasm in differences[:20]:
        print(f"  Byte {pos:5d}: 0x{orig:02x} → 0x{reasm:02x}")

    if len(differences) > 20:
        print(f"  ... and {len(differences) - 20} more")

    print(f"\n  Total differences: {len(differences):,} bytes ({100*len(differences)/original_size:.2f}%)")

    # Acceptable difference threshold
    if len(differences) <= max_acceptable_diff:
        print(f"{Colors.YELLOW}⚠ Minor differences acceptable (≤{max_acceptable_diff} bytes){Colors.RESET}")
        return True
    else:
        print(f"{Colors.RED}✗ FAILED: Too many byte differences{Colors.RESET}")
        return False


def run_test(config: TestConfig, output_dir: Path, skip_reassembly: bool = False) -> bool:
    """
    Run a single round-trip test.

    Returns:
        True if test passed
    """
    print(f"\n{Colors.BLUE}{'='*60}{Colors.RESET}")
    print(f"{Colors.BLUE}{Colors.BOLD}{config.name} Round-Trip Validation{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*60}{Colors.RESET}\n")

    test_output_dir = output_dir / config.name.replace(" ", "_").replace("(", "").replace(")", "").lower()
    test_output_dir.mkdir(parents=True, exist_ok=True)

    # Step 1: Disassemble
    print(f"{Colors.GREEN}Step 1: Disassembling {config.binary_path}{Colors.RESET}")
    success, asm_path = disassemble(config, test_output_dir)

    if not success:
        return False

    print()

    if skip_reassembly:
        print(f"{Colors.YELLOW}Step 2: Skipped (--skip-reassembly){Colors.RESET}")
        print(f"{Colors.YELLOW}Step 3: Skipped (no reassembled binary){Colors.RESET}")
        return True

    # Step 2: Reassemble
    print(f"{Colors.GREEN}Step 2: Reassembling with {config.assembler}{Colors.RESET}")
    success, bin_path = reassemble(config, asm_path, test_output_dir)

    if not success:
        return False

    print()

    # Step 3: Compare
    print(f"{Colors.GREEN}Step 3: Comparing binaries{Colors.RESET}")
    return compare_binaries(Path(config.binary_path), bin_path)


def main():
    parser = argparse.ArgumentParser(
        description="Round-trip validation tests for Sourcerer disassembler",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                     # Run all tests
  %(prog)s --test zaxxon       # Run ZAXXON test only
  %(prog)s --skip-reassembly   # Only test disassembly
  %(prog)s --no-color          # Disable colored output
        """
    )

    parser.add_argument('--test',
                       help='Run specific test (zaxxon, grafix, gamebg)')
    parser.add_argument('--skip-reassembly',
                       action='store_true',
                       help='Skip reassembly step (only test disassembly)')
    parser.add_argument('--output-dir',
                       default='test_output/roundtrip',
                       help='Output directory for test artifacts')
    parser.add_argument('--no-color',
                       action='store_true',
                       help='Disable colored output')
    parser.add_argument('--verbose',
                       action='store_true',
                       help='Verbose output')

    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        Colors.disable()

    # Filter tests if specific test requested
    tests = TEST_CONFIGS
    if args.test:
        test_name = args.test.lower()
        tests = [t for t in TEST_CONFIGS if test_name in t.name.lower()]
        if not tests:
            print(f"{Colors.RED}Error: Test '{args.test}' not found{Colors.RESET}")
            print(f"\nAvailable tests:")
            for config in TEST_CONFIGS:
                print(f"  - {config.name}")
            return 1

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Run tests
    results = {}
    for config in tests:
        success = run_test(config, output_dir, args.skip_reassembly)
        results[config.name] = success

    # Summary
    print(f"\n{Colors.BLUE}{'='*60}{Colors.RESET}")
    print(f"{Colors.BLUE}{Colors.BOLD}Test Summary{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*60}{Colors.RESET}\n")

    for name, success in results.items():
        status = f"{Colors.GREEN}✓ PASS{Colors.RESET}" if success else f"{Colors.RED}✗ FAIL{Colors.RESET}"
        print(f"  {status}  {name}")

    passed = sum(results.values())
    total = len(results)

    print(f"\n{passed}/{total} tests passed")

    if passed == total:
        print(f"\n{Colors.GREEN}✓ All tests passed!{Colors.RESET}\n")
        return 0
    else:
        print(f"\n{Colors.RED}✗ Some tests failed{Colors.RESET}\n")
        return 1


if __name__ == '__main__':
    sys.exit(main())
