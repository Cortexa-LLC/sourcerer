# Sourcerer Coding Standards

**Modern C++ Disassembler for Retro Computing Platforms**

This project uses a **two-tier rule system** for maintaining code quality:

## Tier 1: Shared Standards (Submodule)

All files **without** the `PROJECT-` prefix come from the [Cortexa LLC Clean Code Standards](https://github.com/Cortexa-LLC/clean-code) repository:

- **01-design-principles.md** - Beck's Four Rules, Tell Don't Ask, Dependency Injection
- **02-solid-principles.md** - Complete SOLID principles with examples
- **03-refactoring.md** - Code smells catalog and refactoring techniques
- **04-testing.md** - Test Pyramid, test doubles, testing best practices
- **07-development-practices.md** - YAGNI, CI, Technical Debt management
- **08-deployment-patterns.md** - Feature Toggles, Blue-Green, Canary Release
- **lang-cpp.md** - Effective C++ (55 items) + C++ Core Guidelines

These standards apply to **all Cortexa projects**.

## Tier 2: Project-Specific Rules (This Project)

Files with `PROJECT-` prefix are specific to Sourcerer:

- **[PROJECT-sourcerer.md](PROJECT-sourcerer.md)** - Formatting, style, and conventions
- **[PROJECT-architecture.md](PROJECT-architecture.md)** - Plugin architecture and CPU-agnostic design

## How Claude Code Uses Both Tiers

**Claude Code automatically discovers and applies both:**

1. ✅ Reads all `.md` files in this `.clinerules/` directory
2. ✅ Applies shared standards from submodule (design principles, SOLID, C++ guidelines)
3. ✅ Applies project-specific rules (formatting, architecture patterns)
4. ✅ No additional configuration needed!

**During code review and generation, Claude will:**
- Enforce 2-space indentation (project rule)
- Apply SOLID principles (shared rule)
- Ensure CPU-agnostic design (project rule)
- Follow C++ Core Guidelines (shared rule)
- Check for code smells (shared rule)
- Validate plugin architecture (project rule)

## Rule Priority

When rules conflict (rare), **project-specific rules take precedence**:

**Example:**
- **Shared:** C++ Core Guidelines suggest 4-space indentation
- **Project:** Sourcerer requires 2-space indentation
- **Result:** Use 2-space indentation (project wins)

In practice, project rules usually **extend** rather than contradict shared rules.

## Updating Standards

### Update Shared Standards

```bash
# Update to latest Cortexa standards
git submodule update --remote .clinerules
git add .clinerules
git commit -m "Update to latest clean code standards"
```

### Update Project-Specific Rules

```bash
# Edit project files directly
vim .clinerules/PROJECT-sourcerer.md

# Commit changes
git add .clinerules/PROJECT-*.md
git commit -m "Update project coding rules"
```

## Quick Reference

**Formatting:** See [PROJECT-sourcerer.md](PROJECT-sourcerer.md#formatting)
**Architecture:** See [PROJECT-architecture.md](PROJECT-architecture.md)
**SOLID Principles:** See [02-solid-principles.md](02-solid-principles.md)
**C++ Guidelines:** See [lang-cpp.md](lang-cpp.md)
**Code Smells:** See [03-refactoring.md](03-refactoring.md)

---

**Both tiers work together to maintain high code quality across all Cortexa projects while respecting Sourcerer's unique requirements.**
