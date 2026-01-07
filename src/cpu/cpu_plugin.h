// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_CPU_CPU_PLUGIN_H_
#define SOURCERER_CPU_CPU_PLUGIN_H_

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "core/instruction.h"

namespace sourcerer {
namespace cpu {

// Forward declaration
class CpuState;

// CPU variant types
enum class CpuVariant {
  MOS_6502,     // Original NMOS 6502
  WDC_65C02,    // CMOS 65C02 with additional instructions
  WDC_65816,    // 16-bit 65816 (Apple IIgs)
  MOTOROLA_6809,
  ZILOG_Z80,
};

// Interrupt vector information
struct InterruptVector {
  uint32_t address;      // Address of the vector in memory
  std::string name;      // Name of the interrupt (e.g., "IRQ", "NMI", "RESET")
};

// Analysis capabilities interface
// CPU plugins can provide CPU-specific analysis hints
struct AnalysisCapabilities {
  // Does this CPU have interrupt vectors?
  bool has_interrupt_vectors = false;

  // Does this CPU support subroutine calls?
  bool has_subroutines = true;

  // Typical alignment for code (1 = byte-aligned, 2 = word-aligned)
  uint32_t code_alignment = 1;
};

// Abstract CPU plugin interface
class CpuPlugin {
 public:
  virtual ~CpuPlugin() = default;

  // Plugin identification
  virtual std::string Name() const = 0;
  virtual std::vector<std::string> Aliases() const = 0;
  virtual CpuVariant GetVariant() const = 0;

  // Disassemble one instruction at the given address
  // Returns the disassembled instruction
  virtual core::Instruction Disassemble(const uint8_t* data, size_t size,
                                        uint32_t address) const = 0;

  // Get instruction size without full disassembly (for quick scanning)
  virtual size_t GetInstructionSize(const uint8_t* data, size_t size,
                                    uint32_t address) = 0;

  // CPU capabilities
  virtual bool Supports16Bit() const { return false; }
  virtual uint32_t MaxAddress() const { return 0xFFFF; }
  virtual uint32_t AddressMask() const { return 0xFFFF; }

  // NEW: CPU-specific code analysis methods (SOLID architecture)
  // These methods allow CPU plugins to provide CPU-specific analysis hints
  // without the analyzer needing to know about specific CPU architectures

  // Get analysis capabilities for this CPU
  virtual AnalysisCapabilities GetAnalysisCapabilities() const {
    return AnalysisCapabilities();
  }

  // Get interrupt vector table locations for this CPU
  // Returns empty vector if CPU doesn't have interrupt vectors
  virtual std::vector<InterruptVector> GetInterruptVectors() const {
    return {};
  }

  // Read a vector target address from memory
  // Handles CPU-specific endianness and vector format
  // Returns 0 if address is invalid or vector is not readable
  virtual uint32_t ReadVectorTarget(const uint8_t* data, size_t size,
                                    uint32_t vector_address) const {
    (void)data;
    (void)size;
    (void)vector_address;
    return 0;
  }

  // Check if an address looks like a subroutine entry point
  // Uses CPU-specific patterns (e.g., PSHS for 6809, PHP/PHA for 6502)
  // Returns true if the byte sequence matches typical subroutine patterns
  virtual bool LooksLikeSubroutineStart(const uint8_t* data, size_t size,
                                        uint32_t address) const {
    (void)data;
    (void)size;
    (void)address;
    return false;  // Default: no pattern matching
  }

  // Check if a region looks like valid executable code
  // Attempts to disassemble a few instructions and validates them
  // Returns true if the region appears to contain valid instructions
  virtual bool IsLikelyCode(const uint8_t* data, size_t size,
                           uint32_t address, size_t scan_length = 16) const {
    (void)data;
    (void)size;
    (void)address;
    (void)scan_length;
    return false;  // Default: no validation
  }

  // Create a CPU-specific state object for execution simulation
  // Returns a unique_ptr to a CpuState implementation
  virtual std::unique_ptr<CpuState> CreateCpuState() const = 0;
};

// Factory function type for creating CPU plugins
using CpuPluginFactory = std::unique_ptr<CpuPlugin> (*)();

}  // namespace cpu
}  // namespace sourcerer

#endif  // SOURCERER_CPU_CPU_PLUGIN_H_
