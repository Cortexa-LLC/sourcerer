# Sourcerer Project-Specific Coding Rules

This directory contains Sourcerer's project-specific coding rules that complement the shared standards from the [Cortexa LLC Clean Code Standards](https://github.com/Cortexa-LLC/clean-code) submodule.

## Two-Tier Rule System

Sourcerer uses a two-tier rule system:

**Tier 1: Shared Standards** (in `.clinerules/` submodule)
- Core design principles (SOLID, refactoring, etc.)
- C++ language-specific guidelines (Effective C++, Core Guidelines)
- Python, JavaScript, Java, Kotlin standards
- Universal best practices

**Tier 2: Project-Specific Rules** (this directory)
- `PROJECT-README.md` - Overview of Sourcerer's rule structure
- `PROJECT-sourcerer.md` - Sourcerer-specific formatting and conventions
- `PROJECT-architecture.md` - Plugin architecture patterns and constraints

## How Claude Code Discovers These Rules

Claude Code automatically discovers all `.md` files in the `.clinerules/` directory. To make these project-specific rules available to Claude:

**The files from this directory are automatically copied to `.clinerules/` during development.**

The files in `.clinerules/` are:
- Git-ignored by the submodule (via `.clinerules/.gitignore`)
- Not tracked by the parent repository (Git limitation with submodules)
- Local working files that Claude Code discovers and applies

## When to Copy These Files

These files should already exist in your `.clinerules/` directory. If they're missing:

```bash
# Copy project-specific rules to .clinerules/ for Claude Code to discover
cp docs/project-rules/PROJECT-*.md .clinerules/
```

## Maintaining Project Rules

To update project-specific rules:

1. Edit the files in `.clinerules/PROJECT-*.md` (working copies)
2. When ready to commit changes:
   ```bash
   # Copy updated files back to docs/
   cp .clinerules/PROJECT-*.md docs/project-rules/

   # Commit to version control
   git add docs/project-rules/
   git commit -m "Update project-specific coding rules"
   ```

## Architecture

```
sourcerer/
├── .clinerules/                    # Git submodule + working files
│   ├── (submodule content)         # Shared standards (tracked by submodule)
│   ├── PROJECT-README.md           # Working copy (git-ignored by submodule)
│   ├── PROJECT-sourcerer.md        # Working copy (git-ignored by submodule)
│   └── PROJECT-architecture.md     # Working copy (git-ignored by submodule)
└── docs/project-rules/             # Version-controlled copies
    ├── README.md                   # This file
    ├── PROJECT-README.md           # Source of truth
    ├── PROJECT-sourcerer.md        # Source of truth
    └── PROJECT-architecture.md     # Source of truth
```

## Why This Design?

Git submodules don't allow the parent repository to track individual files within the submodule directory. This design:

- Keeps shared standards in a submodule (easy to update across projects)
- Tracks project-specific rules in version control (in `docs/project-rules/`)
- Provides working copies in `.clinerules/` for Claude Code to discover
- Maintains clear separation between shared and project-specific rules

## Updating Shared Standards

To update the shared standards from upstream:

```bash
# Pull latest shared standards
git submodule update --remote .clinerules

# Commit the submodule update
git add .clinerules
git commit -m "Update to latest clean code standards"
```

---

**Made with care by Cortexa LLC**
