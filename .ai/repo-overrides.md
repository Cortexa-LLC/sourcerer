# Repository-Specific Overrides

**Project:** Sourcerer
**Last Updated:** 2026-01-08

---

## Overview

This file contains Sourcerer-specific overrides and guidance that supplement the ai-pack framework defaults.

**Note:** Parallel agent execution (3+ independent subtasks, max 4 workers) is now the DEFAULT in ai-pack. This file focuses on Sourcerer-specific details only.

---

## C++ Test File Integration Strategy

When multiple parallel workers write to test files:

### Preferred Approach: Section Markers

Each worker should use clear C++ comment markers to delineate their section:

```cpp
// ============================================================================
// Work Package 2: Branch Instructions (Agent 2)
// ============================================================================

TEST(EdtasmFormatterTest, BranchToLabel) {
  // Test implementation...
}

// More tests...
```

**Benefits:**
- Clear ownership boundaries
- Easy to review per-worker contributions
- Reduces merge conflicts
- Maintains code organization

### Alternative Approaches

- **Option B:** Workers output test code as text blocks, orchestrator integrates
- **Option C:** Sequential writes (slower, use only if conflicts detected)

---

## Sourcerer-Specific Task Patterns

### Code Coverage Improvement Tasks

**Pattern:** Split by formatter or component type

Examples:
- Multiple formatters → One worker per formatter (e.g., EdtasmFormatter, MerlinFormatter)
- Large formatter test suite → Split by feature category:
  - Labels & Comments (~7-10 tests)
  - Branch Instructions (~9-12 tests)
  - Data Formatting (~5-8 tests)
  - Advanced Features (~10-15 tests)

**Target:** ~5-15 tests per worker for balanced workload

### Feature Implementation Tasks

**Sourcerer-specific guidance:**
- CPU plugin implementations → Parallelizable (independent plugins)
- Formatter implementations → Parallelizable (different output formats)
- Analyzer enhancements → Sequential if modifying shared `CodeAnalyzer` base

### Bug Fix Tasks

**Default:** Sequential (typically focused on single issue)

---

## Sourcerer Build and Verification

### Required Verification Steps

After parallel worker completion, verify:

```bash
# 1. Build check
cmake --build build_coverage

# 2. Run all tests
cd build_coverage
ctest --output-on-failure

# 3. Generate coverage report
# (Run coverage commands per project setup)

# 4. Check coverage meets target (80-90%)
```

**Integration checks:**
- No duplicate test names across worker sections
- Consistent C++ style (2-space indentation)
- All `#include` directives at file top
- Test fixtures used consistently

---

## Sourcerer-Specific Examples

### Example 1: Formatter Test Suite (Parallel)

```
Task: Add unit tests for EdtasmFormatter (40 tests needed)

Work Packages (4 workers):
  WP1: Labels & Comments tests (10 tests) ← Worker 1
  WP2: Branch Instructions (12 tests) ← Worker 2
  WP3: Data Formatting (8 tests) ← Worker 3
  WP4: Advanced Features (10 tests) ← Worker 4

Files: tests/test_edtasm_formatter.cpp
Pattern: Each worker adds section with C++ markers
Result: Single file with 4 clearly marked sections
```

### Example 2: Multiple Formatters (Parallel)

```
Task: Add tests for 3 formatters (80% coverage target)

Work Packages (3 workers):
  WP1: EdtasmFormatter tests → tests/test_edtasm_formatter.cpp ← Worker 1
  WP2: MerlinFormatter tests → tests/test_merlin_formatter.cpp ← Worker 2
  WP3: ScmasmFormatter tests → tests/test_scmasm_formatter.cpp ← Worker 3

Files: Separate test files (no conflicts)
Result: 3 complete test files, independent verification
```

### Example 3: Refactoring (Sequential - Do NOT Parallelize)

```
Task: Refactor Formatter base class interface

Why Sequential:
- Changes affect all formatter subclasses
- Subclass updates depend on base class changes
- High risk of conflicts if parallelized

Action: Single worker, incremental commits
```

---

**Override Version:** 2.0
**Last Updated:** 2026-01-08
**Status:** Active

**Changes from v1.0:**
- Removed redundant parallel execution policy (now in ai-pack defaults)
- Removed generic coordination protocol (now in ai-pack defaults)
- Removed generic performance targets (now in ai-pack defaults)
- Focused exclusively on Sourcerer-specific patterns and guidance
