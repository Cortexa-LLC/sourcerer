#!/usr/bin/env python3
"""Comprehensive integration testing for all supported platforms"""

import subprocess
import sys
from pathlib import Path


class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[0;32m'
    BLUE = '\033[0;34m'
    RED = '\033[0;31m'
    YELLOW = '\033[1;33m'
    BOLD = '\033[1m'
    NC = '\033[0m'  # No Color


def run_test_script(script_name):
    """Run a test script and return exit code"""
    script_path = Path(__file__).parent / script_name

    if not script_path.exists():
        print(f"{Colors.YELLOW}⚠ {script_name} not found{Colors.NC}")
        return None

    result = subprocess.run([sys.executable, str(script_path)])
    return result.returncode


def main():
    """Main integration test function"""
    print()
    print(f"{Colors.BOLD}{Colors.BLUE}{'═' * 47}{Colors.NC}")
    print(f"{Colors.BOLD}{Colors.BLUE}  Sourcerer Integration Test Suite{Colors.NC}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'═' * 47}{Colors.NC}")
    print()

    # Build first
    print(f"{Colors.BLUE}Building Sourcerer...{Colors.NC}")
    project_root = Path(__file__).parent.parent.parent
    result = subprocess.run(
        ["cmake", "--build", "build"],
        cwd=str(project_root),
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print(f"{Colors.RED}✗ Build failed{Colors.NC}")
        print(result.stderr)
        return 1

    # Show last 5 lines of build output
    build_lines = result.stdout.splitlines()
    for line in build_lines[-5:]:
        print(line)

    print(f"{Colors.GREEN}✓ Build successful{Colors.NC}")
    print()

    # Track results
    platforms_passed = 0
    platforms_failed = 0

    # Test 1: CoCo (6809)
    print(f"{Colors.BOLD}{'━' * 44}{Colors.NC}")
    print(f"{Colors.BOLD}Platform 1/3: CoCo (Motorola 6809){Colors.NC}")
    print(f"{Colors.BOLD}{'━' * 44}{Colors.NC}")
    print()

    exit_code = run_test_script("test_coco.py")
    print()

    if exit_code == 0:
        print(f"{Colors.GREEN}✓ CoCo platform tests passed{Colors.NC}")
        platforms_passed += 1
    elif exit_code is None:
        print(f"{Colors.YELLOW}⚠ CoCo tests skipped{Colors.NC}")
        platforms_failed += 1
    else:
        print(f"{Colors.RED}✗ CoCo platform tests failed{Colors.NC}")
        platforms_failed += 1
    print()

    # Test 2: Apple II (6502)
    print(f"{Colors.BOLD}{'━' * 44}{Colors.NC}")
    print(f"{Colors.BOLD}Platform 2/3: Apple II (MOS 6502){Colors.NC}")
    print(f"{Colors.BOLD}{'━' * 44}{Colors.NC}")
    print()

    exit_code = run_test_script("test_apple2.py")
    print()

    if exit_code == 0:
        print(f"{Colors.GREEN}✓ Apple II platform tests passed{Colors.NC}")
        platforms_passed += 1
    elif exit_code is None:
        print(f"{Colors.YELLOW}⚠ Apple II tests skipped{Colors.NC}")
        platforms_failed += 1
    else:
        print(f"{Colors.RED}✗ Apple II platform tests failed{Colors.NC}")
        platforms_failed += 1
    print()

    # Test 3: TRS-80 Model III (Z80)
    print(f"{Colors.BOLD}{'━' * 44}{Colors.NC}")
    print(f"{Colors.BOLD}Platform 3/3: TRS-80 Model III (Z80){Colors.NC}")
    print(f"{Colors.BOLD}{'━' * 44}{Colors.NC}")
    print()

    exit_code = run_test_script("test_model3.py")
    print()

    if exit_code == 0:
        print(f"{Colors.YELLOW}○ TRS-80 tests skipped (not yet implemented){Colors.NC}")
        # Don't count as pass or fail
    elif exit_code is None:
        print(f"{Colors.YELLOW}⚠ TRS-80 tests skipped{Colors.NC}")
        # Don't count as failure if Z80 not implemented yet
    else:
        print(f"{Colors.RED}✗ TRS-80 platform tests failed{Colors.NC}")
        platforms_failed += 1
    print()

    # Final Summary
    print(f"{Colors.BOLD}{'━' * 44}{Colors.NC}")
    print(f"{Colors.BOLD}{Colors.BLUE}Integration Test Summary{Colors.NC}")
    print(f"{Colors.BOLD}{'━' * 44}{Colors.NC}")
    print()
    print(f"Platforms passed: {Colors.GREEN}{platforms_passed}{Colors.NC}")
    print(f"Platforms failed: {Colors.RED}{platforms_failed}{Colors.NC}")
    print()

    if platforms_failed == 0:
        print(f"{Colors.GREEN}{Colors.BOLD}✓ All integration tests passed!{Colors.NC}")
        print()
        return 0
    else:
        print(f"{Colors.RED}{Colors.BOLD}✗ Some integration tests failed{Colors.NC}")
        print()
        return 1


if __name__ == "__main__":
    sys.exit(main())
