#!/usr/bin/env python3
"""Test Apple II platform support with sample binaries"""

import subprocess
import sys
from pathlib import Path


class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[0;32m'
    BLUE = '\033[0;34m'
    RED = '\033[0;31m'
    YELLOW = '\033[1;33m'
    NC = '\033[0m'  # No Color


def test_binary(cpu, platform, format_type, input_file, output_file, verbose=True):
    """Test disassembly of a binary file"""
    project_root = Path(__file__).parent.parent.parent
    cmd = [
        str(project_root / "build" / "sourcerer"),
        "--cpu", cpu,
        "--platform", platform,
        "--format", format_type,
        "--input", str(input_file),
        "--output", str(output_file)
    ]

    if verbose:
        cmd.append("--verbose")

    result = subprocess.run(cmd, capture_output=True, text=True)

    if output_file.exists():
        line_count = len(output_file.read_text().splitlines())
        return True, line_count
    else:
        return False, 0


def main():
    """Main test function"""
    project_root = Path(__file__).parent.parent.parent
    output_dir = project_root / "test_output"
    samples_dir = project_root / "samples" / "apple2"

    print(f"{Colors.BLUE}Testing Apple II 6502 Platform Support{Colors.NC}")
    print("=" * 40)

    # Create output directory
    output_dir.mkdir(exist_ok=True)

    tests_passed = 0
    tests_failed = 0

    # Test 1: GRAFIX.bin (Merlin format)
    print(f"\n{Colors.GREEN}Test 1: Disassembling GRAFIX.bin (Merlin format){Colors.NC}")
    success, lines = test_binary(
        "6502", "apple2", "merlin",
        samples_dir / "GRAFIX.bin",
        output_dir / "grafix_merlin.asm"
    )

    if success:
        print(f"{Colors.GREEN}✓ Success!{Colors.NC} Generated {lines} lines (Merlin format)")
        tests_passed += 1
    else:
        print(f"{Colors.RED}✗ Failed{Colors.NC} - Merlin output not created")
        tests_failed += 1

    # Test 2: GRAFIX.bin (SCMASM format)
    print(f"\n{Colors.GREEN}Test 2: Disassembling GRAFIX.bin (SCMASM format){Colors.NC}")
    success, lines = test_binary(
        "6502", "apple2", "scmasm",
        samples_dir / "GRAFIX.bin",
        output_dir / "grafix_scmasm.asm"
    )

    if success:
        print(f"{Colors.GREEN}✓ Success!{Colors.NC} Generated {lines} lines (SCMASM format)")
        tests_passed += 1
    else:
        print(f"{Colors.RED}✗ Failed{Colors.NC} - SCMASM output not created")
        tests_failed += 1

    # Test 3: GAMEBG.bin (Merlin format)
    print(f"\n{Colors.GREEN}Test 3: Disassembling GAMEBG.bin (Merlin format){Colors.NC}")
    success, lines = test_binary(
        "6502", "apple2", "merlin",
        samples_dir / "GAMEBG.bin",
        output_dir / "gamebg_merlin.asm"
    )

    if success:
        print(f"{Colors.GREEN}✓ Success!{Colors.NC} Generated {lines} lines")
        tests_passed += 1
    else:
        print(f"{Colors.RED}✗ Failed{Colors.NC} - Output not created")
        tests_failed += 1

    # Summary
    print("\n" + "=" * 40)
    print(f"{Colors.BLUE}Apple II Test Summary{Colors.NC}")
    print("=" * 40)
    print(f"Tests passed: {Colors.GREEN}{tests_passed}{Colors.NC}")
    print(f"Tests failed: {Colors.RED}{tests_failed}{Colors.NC}")

    if tests_failed == 0:
        print(f"\n{Colors.GREEN}✓ All Apple II tests passed!{Colors.NC}")
        return 0
    else:
        print(f"\n{Colors.RED}✗ Some tests failed{Colors.NC}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
