#!/usr/bin/env python3
"""Test CoCo platform support with ZAXXON.BIN"""

import os
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


def run_command(cmd, description):
    """Run a command and return success status"""
    print(f"\n{Colors.GREEN}{description}{Colors.NC}")
    result = subprocess.run(cmd, shell=False, capture_output=False)
    return result.returncode == 0


def main():
    """Main test function"""
    project_root = Path(__file__).parent.parent.parent

    # Get test disk path from environment or use defaults
    disk_path_env = os.environ.get('ZAXXON_DISK_PATH')
    if disk_path_env:
        disk_path = Path(disk_path_env)
    else:
        # Try samples directory first, then user Downloads
        disk_path = project_root / "samples" / "coco" / "ZAXXON.DSK"
        if not disk_path.exists():
            disk_path = Path.home() / "Downloads" / "Zaxxon (Datasoft)" / "ZAXXON.DSK"

    # Skip test if disk not found
    if not disk_path.exists():
        print(f"{Colors.YELLOW}⚠ ZAXXON.DSK not found{Colors.NC}")
        print(f"{Colors.YELLOW}  Tried: {disk_path}{Colors.NC}")
        print(f"{Colors.YELLOW}  Run 'python setup.py' to configure test files{Colors.NC}")
        print(f"{Colors.YELLOW}  Or set ZAXXON_DISK_PATH environment variable{Colors.NC}")
        print(f"{Colors.YELLOW}  Skipping CoCo tests{Colors.NC}")
        return 0

    output_dir = project_root / "test_output"

    print(f"{Colors.BLUE}Testing CoCo 6809 Platform Support{Colors.NC}")
    print("=" * 40)

    # Create output directory
    output_dir.mkdir(exist_ok=True)

    # Find cocofs tool
    cocofs_path = os.environ.get('COCOFS_PATH', '/usr/local/bin/cocofs')
    if not Path(cocofs_path).exists():
        # Try to find in PATH
        import shutil
        cocofs_path = shutil.which('cocofs')
        if not cocofs_path:
            print(f"{Colors.YELLOW}⚠ cocofs tool not found{Colors.NC}")
            print(f"{Colors.YELLOW}  Install cocofs or set COCOFS_PATH environment variable{Colors.NC}")
            print(f"{Colors.YELLOW}  Skipping CoCo tests{Colors.NC}")
            return 0

    # Test 1: List files on disk
    print(f"\n{Colors.GREEN}Test 1: Listing files on ZAXXON.DSK{Colors.NC}")
    subprocess.run([cocofs_path, str(disk_path), "ls"])

    # Test 2: Disassemble ZAXXON.BIN
    print(f"\n{Colors.GREEN}Test 2: Disassembling ZAXXON.BIN{Colors.NC}")
    output_file = output_dir / "zaxxon.asm"

    cmd = [
        str(project_root / "build" / "sourcerer"),
        "--cpu", "6809",
        "--platform", "coco",
        "--format", "edtasm",
        "--disk",
        "--file", "ZAXXON.BIN",
        "--input", str(disk_path),
        "--output", str(output_file),
        "--verbose"
    ]

    result = subprocess.run(cmd, capture_output=False)

    # Check if output was created
    if output_file.exists():
        line_count = len(output_file.read_text().splitlines())
        print(f"\n{Colors.GREEN}✓ Success!{Colors.NC} Disassembly created at {output_file}")
        print(f"\nFirst 30 lines of output:")
        print("-" * 25)

        lines = output_file.read_text().splitlines()
        for line in lines[:30]:
            print(line)
        print("...")
        print(f"\nFile size: {line_count} lines")

        return 0
    else:
        print(f"{Colors.RED}✗ Failed{Colors.NC} - Output file not created")
        return 1


if __name__ == "__main__":
    sys.exit(main())
