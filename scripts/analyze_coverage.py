#!/usr/bin/env python3
"""
Coverage analysis script for Sourcerer project.
Parses gcov output and generates coverage summary by module.
"""

import re
import subprocess
import sys
from pathlib import Path
from collections import defaultdict

def parse_gcov_output(output):
    """Parse gcov output to extract coverage data."""
    coverage_data = []
    lines = output.split('\n')

    for line in lines:
        if 'Lines executed:' in line:
            match = re.search(r'Lines executed:([\d.nan]+)% of (\d+)', line)
            if match and match.group(1) != 'nan':
                pct = float(match.group(1))
                lines_count = int(match.group(2))
                covered = int(lines_count * pct / 100)
                coverage_data.append((pct, lines_count, covered))

    return coverage_data

def main():
    if len(sys.argv) < 2:
        print("Usage: analyze_coverage.py <build_directory>")
        sys.exit(1)

    build_dir = Path(sys.argv[1])

    # Define modules to analyze
    modules = {
        "Formatters": [
            "CMakeFiles/formatters.dir/src/output/edtasm_formatter.cpp.gcno",
            "CMakeFiles/formatters.dir/src/output/scmasm_formatter.cpp.gcno",
            "CMakeFiles/formatters.dir/src/output/merlin_formatter.cpp.gcno",
            "CMakeFiles/formatters.dir/src/output/data_collector.cpp.gcno",
            "CMakeFiles/formatters.dir/src/output/address_analyzer.cpp.gcno",
            "CMakeFiles/formatters.dir/src/output/label_resolver.cpp.gcno",
        ],
        "Analysis": [
            "CMakeFiles/analysis.dir/src/analysis/code_analyzer.cpp.gcno",
            "CMakeFiles/analysis.dir/src/analysis/execution_simulator.cpp.gcno",
            "CMakeFiles/analysis.dir/src/analysis/label_generator.cpp.gcno",
            "CMakeFiles/analysis.dir/src/analysis/xref_builder.cpp.gcno",
            "CMakeFiles/analysis.dir/src/analysis/hints_parser.cpp.gcno",
        ],
        "CPU": [
            "CMakeFiles/cpu_plugins.dir/src/cpu/m6809/cpu_6809.cpp.gcno",
            "CMakeFiles/cpu_plugins.dir/src/cpu/m6809/opcodes_6809.cpp.gcno",
            "CMakeFiles/cpu_plugins.dir/src/cpu/m6809/cpu_state_6809.cpp.gcno",
            "CMakeFiles/cpu_plugins.dir/src/cpu/m6502/cpu_6502.cpp.gcno",
            "CMakeFiles/cpu_plugins.dir/src/cpu/m6502/opcodes_6502.cpp.gcno",
            "CMakeFiles/cpu_plugins.dir/src/cpu/m6502/cpu_state_6502.cpp.gcno",
        ],
        "Core": [
            "CMakeFiles/sourcerer_core.dir/src/core/binary.cpp.gcno",
            "CMakeFiles/sourcerer_core.dir/src/core/instruction.cpp.gcno",
            "CMakeFiles/sourcerer_core.dir/src/core/address_map.cpp.gcno",
        ],
    }

    print("=" * 90)
    print("SOURCERER COVERAGE REPORT")
    print("=" * 90)

    total_lines = 0
    total_covered = 0
    module_stats = {}

    for module_name, files in modules.items():
        print(f"\n{module_name}:")
        print(f"  {'File':<40} {'Coverage':<10} {'Lines':<8} {'Covered':<8}")
        print(f"  {'-'*80}")

        mod_lines = 0
        mod_covered = 0

        for gcno_file in files:
            gcno_path = build_dir / gcno_file
            if not gcno_path.exists():
                continue

            gcno_dir = gcno_path.parent
            filename = gcno_path.stem.replace('.cpp', '') + '.cpp'

            try:
                result = subprocess.run(
                    ["gcov", "-o", str(gcno_dir), str(gcno_path)],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    cwd=build_dir
                )

                # Find the line with coverage for this specific source file
                for line in result.stdout.split('\n'):
                    if 'Lines executed:' in line and filename in result.stdout:
                        match = re.search(r'Lines executed:([\d.]+)% of (\d+)', line)
                        if match:
                            pct = float(match.group(1))
                            lines = int(match.group(2))
                            covered = int(lines * pct / 100)

                            mod_lines += lines
                            mod_covered += covered
                            total_lines += lines
                            total_covered += covered

                            print(f"  {filename:<40} {pct:>6.2f}%   {lines:>6d}   {covered:>6d}")
                        break
            except Exception as e:
                pass

        if mod_lines > 0:
            mod_pct = (mod_covered / mod_lines) * 100
            module_stats[module_name] = (mod_pct, mod_lines, mod_covered)
            print(f"  {'─'*80}")
            print(f"  {'TOTAL':<40} {mod_pct:>6.2f}%   {mod_lines:>6d}   {mod_covered:>6d}")

    # Overall summary
    print("\n" + "=" * 90)
    if total_lines > 0:
        overall_pct = (total_covered / total_lines) * 100
        lines_needed = int(0.80 * total_lines - total_covered)

        print(f"OVERALL PROJECT:  {overall_pct:>6.2f}%  ({total_covered}/{total_lines} lines)")
        print(f"TARGET:           80.00%")
        print(f"GAP:              {80 - overall_pct:>6.2f}%  ({lines_needed:,} lines needed)")
        print("=" * 90)

        if overall_pct < 80:
            print("\n⚠️  Coverage below 80% target")
            sys.exit(1)
        else:
            print("\n✓ Coverage target achieved!")
            sys.exit(0)
    else:
        print("No coverage data found!")
        sys.exit(1)

if __name__ == "__main__":
    main()
