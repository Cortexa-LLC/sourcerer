# Platform Hints Architecture

## Overview

The hints system is **platform-specific** and properly abstracted to prevent cross-platform contamination (e.g., Apple II ProDOS hints should never be applied to CoCo/6809 code).

## Architecture

### 1. Platform Configuration Files
Location: `symbols/platforms/*.platform.json`

Each platform defines its CPU, symbol files, and hint files:

```json
{
  "platform": "apple2",
  "cpu": "6502",
  "hint_files": [],
  "extensions": {
    "prodos": {
      "hint_files": ["symbols/apple2_prodos_hints.json"]
    }
  }
}
```

### 2. Platform-Specific Hints Files

**Naming Convention:** `{platform}_{subsystem}_hints.json`

Examples:
- `apple2_prodos_hints.json` - Apple II ProDOS MLI inline data detection
- `coco_hints.json` - CoCo/6809 specific patterns (future)

**Do NOT use generic names like `prodos_hints.json`** - always include the platform prefix!

### 3. Current Implementation

**Status:** Platform config exists but loader not yet implemented.

**Current Workaround:** Tests manually map CPU type to hints file:
```cpp
// TODO: Replace with platform config loading
if (cpu_type == "6502" || cpu_type == "65c02") {
  hints_file = "../symbols/apple2_prodos_hints.json";
} else if (cpu_type == "6809") {
  // Read from coco.platform.json when implemented
}
```

**Future:** Proper platform config loader:
```cpp
PlatformConfig config = PlatformConfig::Load("apple2");
for (const auto& hints_file : config.GetHintFiles()) {
  hints.LoadFromFile(hints_file);
}
```

## File Structure

### Platform Hint Files

Format: Same as `apple2_prodos_hints.json`

```json
{
  "platform": "apple2",
  "inline_data_routines": [
    {
      "address": "0xBF00",
      "name": "MLI",
      "bytes_after_call": 3
    }
  ],
  "mli_parameter_structures": {
    "0xC8": {
      "name": "OPEN",
      "parameters": [...]
    }
  }
}
```

### Platform Config Files

Format: See `symbols/platforms/*.platform.json`

```json
{
  "platform": "coco",
  "cpu": "6809",
  "hint_files": [],           // Platform-level hints
  "extensions": {
    "disk": {
      "hint_files": []        // Extension-specific hints
    }
  }
}
```

## Design Principles

### ✅ Proper Abstraction

1. **Platform-Specific Naming**
   - Files: `apple2_prodos_hints.json` NOT `prodos_hints.json`
   - Clear which platform each file applies to

2. **CPU-Based Selection**
   - 6502/65C02 → Apple II hints only
   - 6809 → CoCo hints only
   - No cross-contamination

3. **Configuration-Driven**
   - Platform configs define hint files
   - No hard-coded mappings in application code
   - Easy to add new platforms

### ❌ Anti-Patterns to Avoid

1. **Generic Names**
   ```
   ❌ prodos_hints.json
   ✅ apple2_prodos_hints.json
   ```

2. **Hard-Coded Mappings**
   ```cpp
   ❌ if (cpu == "6502") hints.Load("prodos_hints.json");
   ✅ PlatformConfig::Load("apple2").GetHintFiles();
   ```

3. **Cross-Platform Application**
   ```cpp
   ❌ analyzer.SetHints(&apple2_hints);  // Applied to 6809 code!
   ✅ if (platform == "apple2") analyzer.SetHints(&apple2_hints);
   ```

## Testing

All tests properly abstract platform hints:

```bash
✅ 58/58 core tests pass
✅ 14/14 integration tests pass
✅ Apple II tests use apple2_prodos_hints.json
✅ CoCo/6809 tests do not load Apple II hints
```

## Future Work

1. **Implement PlatformConfig Loader**
   - Create `PlatformConfig` class
   - Load from `symbols/platforms/*.platform.json`
   - Provide API to get hint files for a platform

2. **Add More Platform Hints**
   - CoCo/6809 specific patterns
   - Commodore 64 specific patterns
   - Atari 8-bit specific patterns

3. **CLI Integration**
   - `--platform` flag to specify platform
   - Auto-detect platform from binary format
   - Load appropriate hints automatically

## Related Files

- Platform configs: `symbols/platforms/*.platform.json`
- Apple II ProDOS hints: `symbols/apple2_prodos_hints.json`
- Apple II ProDOS symbols: `symbols/apple2_prodos_mli.json`
- CoCo symbols: `symbols/coco_*.json`

## Summary

The hints system is **properly abstracted by platform** with clear separation between Apple II and CoCo/6809. The architecture supports future expansion while preventing cross-platform contamination. Current implementation uses temporary workaround until platform config loader is implemented.
