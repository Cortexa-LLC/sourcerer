#!/usr/bin/env python3
"""
Convert CoCo ROM symbol files from .asm to JSON format.

This script parses CoCo ROM definition files (cocodefs.asm, auto_symbols_*.asm)
and generates JSON symbol files for the sourcerer disassembler.
"""

import json
import re
import sys
from pathlib import Path
from typing import List, Dict, Optional

class SymbolConverter:
    def __init__(self):
        self.symbols = []

    def classify_symbol_type(self, address: int, name: str, is_constant: bool) -> str:
        """Classify symbol type based on address range and name."""
        if is_constant:
            return "constant"

        # Zero page / direct page
        if 0x0000 <= address <= 0x00FF:
            return "zero_page"

        # I/O and hardware registers
        if 0xFF00 <= address <= 0xFFFF:
            return "io_port"

        # ROM routines
        if 0x8000 <= address <= 0xFFFF:
            return "routine"

        # Default to data
        return "data"

    def parse_equ_line(self, line: str) -> Optional[Dict]:
        """Parse an EQU line and extract symbol information."""
        # Match pattern: LABEL EQU $ADDRESS or LABEL EQU VALUE ; Comment
        match = re.match(r'^(\w+)\s+EQU\s+\$([0-9A-Fa-f]+)\s*;?\s*(.*?)$', line.strip())
        if not match:
            # Try decimal value
            match = re.match(r'^(\w+)\s+EQU\s+(\d+)\s*;?\s*(.*?)$', line.strip())
            if not match:
                return None

            name = match.group(1)
            value = int(match.group(2))
            comment = match.group(3).strip()

            # Decimal values are typically constants, not addresses
            return {
                "name": name,
                "address": f"0x{value:04X}",
                "description": comment if comment else f"Constant: {value}",
                "type": "constant",
                "is_constant": True
            }

        name = match.group(1)
        address = int(match.group(2), 16)
        comment = match.group(3).strip()

        # Determine if this looks like a constant vs an address
        is_constant = address < 256 and name.isupper() and not comment.lower().startswith(('address', 'pointer', 'vector'))

        symbol_type = self.classify_symbol_type(address, name, is_constant)

        return {
            "name": name,
            "address": f"0x{address:04X}",
            "description": comment if comment else name,
            "type": symbol_type
        }

    def convert_file(self, input_path: Path, platform_desc: str) -> Dict:
        """Convert a single .asm file to JSON format."""
        print(f"Processing {input_path.name}...", file=sys.stderr)

        symbols = []

        with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                # Skip empty lines and full-line comments
                line = line.rstrip()
                if not line or line.strip().startswith(';') or line.strip().startswith('*'):
                    continue

                # Parse EQU statements
                symbol = self.parse_equ_line(line)
                if symbol:
                    symbols.append(symbol)

        print(f"  Found {len(symbols)} symbols", file=sys.stderr)

        return {
            "platform": "coco",
            "description": platform_desc,
            "version": "1.0",
            "symbols": symbols
        }

    def filter_by_type(self, symbols_data: Dict, symbol_type: str) -> Dict:
        """Filter symbols by type."""
        filtered_symbols = [s for s in symbols_data["symbols"] if s.get("type") == symbol_type]
        return {
            "platform": symbols_data["platform"],
            "description": f"{symbols_data['description']} - {symbol_type} only",
            "version": symbols_data["version"],
            "symbols": filtered_symbols
        }

    def filter_by_address_range(self, symbols_data: Dict, start: int, end: int, desc_suffix: str) -> Dict:
        """Filter symbols by address range."""
        filtered_symbols = []
        for s in symbols_data["symbols"]:
            try:
                addr = int(s["address"], 16)
                if start <= addr <= end:
                    filtered_symbols.append(s)
            except (ValueError, KeyError):
                continue

        return {
            "platform": symbols_data["platform"],
            "description": f"{symbols_data['description']} - {desc_suffix}",
            "version": symbols_data["version"],
            "symbols": filtered_symbols
        }

def main():
    # Paths
    rom_dir = Path.home() / "Projects/Vintage/CoCo/Source/coco_roms"
    output_dir = Path("symbols")

    # Ensure output directory exists
    output_dir.mkdir(exist_ok=True)

    converter = SymbolConverter()

    # Process cocodefs.asm -> constants
    cocodefs_path = rom_dir / "cocodefs.asm"
    if cocodefs_path.exists():
        data = converter.convert_file(cocodefs_path, "CoCo hardware and constants")

        # Split into constants and hardware
        constants = converter.filter_by_type(data, "constant")
        hardware = converter.filter_by_address_range(data, 0xFF00, 0xFFFF, "hardware registers")
        zeropage = converter.filter_by_address_range(data, 0x0000, 0x00FF, "zero page variables")

        # Write constants
        output_path = output_dir / "coco_constants.json"
        with open(output_path, 'w') as f:
            json.dump(constants, f, indent=2)
        print(f"✓ Created {output_path} ({len(constants['symbols'])} symbols)")

        # Write hardware
        if hardware['symbols']:
            output_path = output_dir / "coco_hardware.json"
            with open(output_path, 'w') as f:
                json.dump(hardware, f, indent=2)
            print(f"✓ Created {output_path} ({len(hardware['symbols'])} symbols)")

        # Write zero page
        if zeropage['symbols']:
            output_path = output_dir / "coco_zeropage.json"
            with open(output_path, 'w') as f:
                json.dump(zeropage, f, indent=2)
            print(f"✓ Created {output_path} ({len(zeropage['symbols'])} symbols)")

    # Process auto_symbols_bas.asm -> BASIC ROM
    bas_path = rom_dir / "auto_symbols_bas.asm"
    if bas_path.exists():
        data = converter.convert_file(bas_path, "CoCo Color BASIC ROM routines")
        output_path = output_dir / "coco_basic.json"
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"✓ Created {output_path} ({len(data['symbols'])} symbols)")

    # Process auto_symbols_extbas.asm -> Extended BASIC ROM
    extbas_path = rom_dir / "auto_symbols_extbas.asm"
    if extbas_path.exists():
        data = converter.convert_file(extbas_path, "CoCo Extended BASIC ROM routines")
        output_path = output_dir / "coco_extbas.json"
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"✓ Created {output_path} ({len(data['symbols'])} symbols)")

    print("\n✓ Symbol conversion complete!")

if __name__ == "__main__":
    main()
