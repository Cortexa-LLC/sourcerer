// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "analysis/entry_point_discovery_strategy.h"

#include "utils/logger.h"

namespace sourcerer {
namespace analysis {

EntryPointDiscoveryStrategy::EntryPointDiscoveryStrategy(
    cpu::CpuPlugin* cpu, const core::Binary* binary)
    : cpu_(cpu), binary_(binary) {}

bool EntryPointDiscoveryStrategy::IsValidAddress(uint32_t address) const {
  uint32_t start = binary_->load_address();
  uint32_t end = start + binary_->size();
  return address >= start && address < end;
}

bool EntryPointDiscoveryStrategy::IsLikelyCode(uint32_t address,
                                               size_t scan_length) const {
  if (!IsValidAddress(address)) return false;

  // Delegate to CPU plugin (SOLID architecture)
  const uint8_t* data = binary_->GetPointer(address);
  size_t remaining = binary_->load_address() + binary_->size() - address;

  return cpu_->IsLikelyCode(data, remaining, address, scan_length);
}

bool EntryPointDiscoveryStrategy::LooksLikeSubroutineStart(uint32_t address) const {
  if (!IsValidAddress(address)) return false;

  // Delegate to CPU plugin (SOLID architecture)
  const uint8_t* data = binary_->GetPointer(address);
  size_t remaining = binary_->load_address() + binary_->size() - address;

  return cpu_->LooksLikeSubroutineStart(data, remaining, address);
}

void EntryPointDiscoveryStrategy::ScanInterruptVectors(
    std::set<uint32_t>* discovered_entry_points) {
  // Get CPU-specific interrupt vectors (SOLID architecture)
  cpu::AnalysisCapabilities caps = cpu_->GetAnalysisCapabilities();
  if (!caps.has_interrupt_vectors) {
    return;  // CPU doesn't have interrupt vectors
  }

  std::vector<cpu::InterruptVector> vectors = cpu_->GetInterruptVectors();

  for (const auto& vec : vectors) {
    uint32_t vec_addr = vec.address;
    if (!IsValidAddress(vec_addr) || !IsValidAddress(vec_addr + 1)) continue;

    const uint8_t* data = binary_->GetPointer(vec_addr);
    size_t size = binary_->load_address() + binary_->size() - vec_addr;

    // Let CPU plugin handle endianness
    uint32_t target = cpu_->ReadVectorTarget(data, size, 0);

    if (target != 0 && IsValidAddress(target) && IsLikelyCode(target)) {
      discovered_entry_points->insert(target);
      LOG_DEBUG("Discovered " + vec.name + " vector at $" +
                std::to_string(vec_addr) + " -> $" + std::to_string(target));
    }
  }
}

void EntryPointDiscoveryStrategy::ScanForSubroutinePatterns(
    core::AddressMap* address_map,
    std::set<uint32_t>* discovered_entry_points,
    std::set<uint32_t>* lea_targets) {
  // Scan UNKNOWN regions for potential subroutine entry points
  uint32_t start = binary_->load_address();
  uint32_t end = start + binary_->size();

  // Sample every N bytes to avoid excessive scanning
  const int SAMPLE_STRIDE = 4;  // Check every 4 bytes

  for (uint32_t addr = start; addr < end; addr += SAMPLE_STRIDE) {
    // Only check UNKNOWN regions (not already classified as CODE or DATA)
    if (address_map->GetType(addr) == core::AddressType::UNKNOWN) {
      if (LooksLikeSubroutineStart(addr)) {
        discovered_entry_points->insert(addr);
        LOG_DEBUG("Discovered likely subroutine at $" + std::to_string(addr));
      }
    }
  }

  // Note: lea_targets is currently unused but kept for API compatibility
  // Future use: Track LEA/LEAX/LEAY target addresses as potential data
  (void)lea_targets;
}

bool EntryPointDiscoveryStrategy::IsCoCoCartridgeSpace(uint32_t address) const {
  // CoCo cartridge ROM space: $C000-$FEFF
  // Reset vector at $FFFE-$FFFF
  return (address >= 0xC000 && address <= 0xFEFF);
}

bool EntryPointDiscoveryStrategy::HasCoCoPreamble(uint32_t address) const {
  // Check for common CoCo machine language program preambles
  if (!IsValidAddress(address) || !IsValidAddress(address + 1)) {
    return false;
  }

  const uint8_t* data = binary_->GetPointer(address);
  if (!data) return false;

  // Check for "DK" signature (Disk BASIC)
  if (data[0] == 0x44 && data[1] == 0x4B) {
    return true;
  }

  // Check for common preamble patterns:
  // PSHS U,Y,X,DP,D,CC (full register save on entry)
  // Opcode: $34 followed by register mask
  if (data[0] == 0x34) {
    return true;
  }

  // ORCC #$50 (disable interrupts - common at program start)
  if (data[0] == 0x1A && data[1] == 0x50) {
    return true;
  }

  // LDS #immediate (set stack pointer - very common first instruction)
  if (data[0] == 0x10 && data[1] == 0xCE) {
    return true;
  }

  // JMP extended (redirect to real entry point)
  if (data[0] == 0x7E) {
    return true;
  }

  return false;
}

void EntryPointDiscoveryStrategy::ScanCoCoCartridgeEntryPoints(
    std::set<uint32_t>* discovered_entry_points) {
  // Cartridge programs typically have entry point at $C000
  uint32_t cart_entry = 0xC000;

  if (IsValidAddress(cart_entry) && IsCoCoCartridgeSpace(cart_entry)) {
    if (IsLikelyCode(cart_entry)) {
      discovered_entry_points->insert(cart_entry);
      LOG_DEBUG("Discovered CoCo cartridge entry point at $C000");
    }
  }

  // Check if binary is loaded in cartridge space
  uint32_t load_addr = binary_->load_address();
  if (IsCoCoCartridgeSpace(load_addr)) {
    // Cartridge ROM - entry point is typically at start
    discovered_entry_points->insert(load_addr);
    LOG_DEBUG("Binary in CoCo cartridge space, adding load address as entry point");
  }
}

void EntryPointDiscoveryStrategy::ScanCoCoStandardEntryPoints(
    std::set<uint32_t>* discovered_entry_points) {
  uint32_t load_addr = binary_->load_address();

  // Standard CoCo machine language program entry patterns:

  // Pattern 1: Load address + 0 (immediate entry)
  if (IsLikelyCode(load_addr)) {
    discovered_entry_points->insert(load_addr);
    LOG_DEBUG("CoCo entry point at load address: $" + std::to_string(load_addr));
  }

  // Pattern 2: Load address + 2 (skip 2-byte preamble/header)
  if (IsValidAddress(load_addr + 2)) {
    const uint8_t* data = binary_->GetPointer(load_addr);
    if (data) {
      // Check if first 2 bytes look like a preamble
      bool has_preamble = (data[0] == 0x00) ||
                          (data[0] == 0x45 && data[1] == 0x58) ||  // "EX"
                          (data[0] == ((load_addr >> 8) & 0xFF));

      if (has_preamble && IsLikelyCode(load_addr + 2)) {
        discovered_entry_points->insert(load_addr + 2);
        LOG_DEBUG("CoCo entry point after 2-byte preamble: $" +
                  std::to_string(load_addr + 2));
      }
    }
  }

  // Pattern 3: Check for DK header (Disk BASIC format)
  if (IsValidAddress(load_addr) && IsValidAddress(load_addr + 1)) {
    const uint8_t* data = binary_->GetPointer(load_addr);
    if (data && data[0] == 0x44 && data[1] == 0x4B) {  // "DK"
      // Entry point typically at offset $09
      if (IsValidAddress(load_addr + 0x09)) {
        discovered_entry_points->insert(load_addr + 0x09);
        LOG_DEBUG("CoCo Disk BASIC format detected, entry at +$09");
      }
    }
  }

  // Pattern 4: Scan for PSHS as subroutine entry markers
  uint32_t end = load_addr + binary_->size();
  for (uint32_t addr = load_addr; addr < end - 1; addr += 2) {
    const uint8_t* data = binary_->GetPointer(addr);
    if (!data) continue;

    // PSHS with multiple registers (opcode $34, mask with multiple bits set)
    if (data[0] == 0x34) {
      uint8_t mask = data[1];
      int bit_count = 0;
      for (int i = 0; i < 8; ++i) {
        if (mask & (1 << i)) bit_count++;
      }

      // If saving 3+ registers, likely a subroutine entry
      if (bit_count >= 3 && IsLikelyCode(addr)) {
        discovered_entry_points->insert(addr);
        LOG_DEBUG("CoCo subroutine entry (PSHS) at $" + std::to_string(addr));
      }
    }
  }

  // Pattern 5: Look for addresses in the binary that point to code
  for (uint32_t addr = load_addr; addr < end - 1; addr += 2) {
    const uint8_t* data = binary_->GetPointer(addr);
    if (!data) continue;

    // Read 16-bit address (6809 is big-endian)
    uint16_t target = (data[0] << 8) | data[1];

    // Check if this points within the binary and looks like code
    if (IsValidAddress(target) && IsLikelyCode(target)) {
      // Additional validation: target should be aligned
      if ((target % 2) == 0) {  // Code typically even-aligned
        discovered_entry_points->insert(target);
        LOG_DEBUG("CoCo potential code pointer at $" + std::to_string(addr) +
                  " -> $" + std::to_string(target));
      }
    }
  }
}

void EntryPointDiscoveryStrategy::DiscoverEntryPoints(
    core::AddressMap* address_map,
    std::set<uint32_t>* discovered_entry_points,
    std::set<uint32_t>* lea_targets) {
  LOG_INFO("Discovering additional entry points...");

  int initial_count = discovered_entry_points->size();

  // Scan CPU-specific interrupt vectors (SOLID architecture)
  ScanInterruptVectors(discovered_entry_points);

  // CoCo-specific entry point detection
  if (cpu_->GetVariant() == cpu::CpuVariant::MOTOROLA_6809) {
    ScanCoCoCartridgeEntryPoints(discovered_entry_points);
    ScanCoCoStandardEntryPoints(discovered_entry_points);
  }

  // Scan for subroutine patterns in UNKNOWN regions
  ScanForSubroutinePatterns(address_map, discovered_entry_points, lea_targets);

  int new_count = discovered_entry_points->size() - initial_count;
  LOG_INFO("Discovered " + std::to_string(new_count) +
           " additional entry point(s)");
}

}  // namespace analysis
}  // namespace sourcerer
