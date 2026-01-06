// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_ANALYSIS_PATTERN_DETECTOR_H_
#define SOURCERER_ANALYSIS_PATTERN_DETECTOR_H_

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "core/address_map.h"
#include "core/instruction.h"
#include "core/symbol_table.h"

namespace sourcerer {
namespace analysis {

// Bit field definition for hardware registers
struct BitField {
  uint8_t bit_number;        // Bit position (0-7)
  std::string name;          // e.g., "IRQ_ENABLE", "MOTOR_ON"
  std::string description;   // Human-readable description
};

// Hardware register definition with bit semantics
struct HardwareRegister {
  uint32_t address;
  std::string name;
  std::string description;
  std::vector<BitField> bits;

  // Quick lookup: bit number -> field
  std::map<uint8_t, const BitField*> bit_map;
};

// Detected pattern types
enum class PatternType {
  SET_BIT,      // LDA reg / ORA #mask / STA reg
  CLEAR_BIT,    // LDA reg / ANDA #mask / STA reg
  TOGGLE_BIT,   // LDA reg / EORA #mask / STA reg
  WRITE_VALUE,  // LDA #value / STA reg
  TEST_BIT,     // LDA reg / ANDA #mask / BEQ/BNE
  ROM_CALL,     // JSR/LBSR/BSR to known ROM routine
};

// Detected pattern result
struct DetectedPattern {
  PatternType type;
  uint32_t start_address;     // First instruction in pattern
  uint32_t end_address;       // Last instruction in pattern
  uint32_t target_register;   // Hardware register being manipulated
  uint8_t bit_mask;           // Bits being manipulated
  std::string comment;        // Generated comment
};

// Base class for platform-specific pattern detection
class PatternDetector {
 public:
  virtual ~PatternDetector() = default;

  // Analyze instruction sequences and add comments to AddressMap
  // symbol_table is optional - if provided, enables ROM routine call detection
  virtual void AnalyzePatterns(
      const std::vector<core::Instruction>& instructions,
      core::AddressMap* address_map,
      const core::SymbolTable* symbol_table = nullptr) = 0;

  // Get platform name
  virtual std::string GetPlatformName() const = 0;

 protected:
  // Helper: Check if address is a hardware register
  bool IsHardwareRegister(uint32_t address) const;

  // Helper: Get register definition
  const HardwareRegister* GetRegister(uint32_t address) const;

  // Helper: Decode bit mask into field names
  std::string DecodeBitMask(uint32_t register_addr, uint8_t mask) const;

  // Helper: Detect JSR/LBSR/BSR to ROM routines
  bool DetectRomCall(
      const core::Instruction& inst,
      const core::SymbolTable* symbol_table,
      DetectedPattern* pattern) const;

  // Hardware register definitions (populated by subclass)
  std::map<uint32_t, HardwareRegister> hardware_registers_;
};

// CoCo-specific pattern detector
class CoCoPatternDetector : public PatternDetector {
 public:
  CoCoPatternDetector();

  void AnalyzePatterns(
      const std::vector<core::Instruction>& instructions,
      core::AddressMap* address_map,
      const core::SymbolTable* symbol_table = nullptr) override;

  std::string GetPlatformName() const override { return "coco"; }

 private:
  void InitializeHardwareRegisters();

  // Pattern detection methods
  bool DetectSetBitPattern(
      const std::vector<core::Instruction>& instructions,
      size_t index,
      DetectedPattern* pattern) const;

  bool DetectClearBitPattern(
      const std::vector<core::Instruction>& instructions,
      size_t index,
      DetectedPattern* pattern) const;

  bool DetectToggleBitPattern(
      const std::vector<core::Instruction>& instructions,
      size_t index,
      DetectedPattern* pattern) const;

  bool DetectWriteValuePattern(
      const std::vector<core::Instruction>& instructions,
      size_t index,
      DetectedPattern* pattern) const;
};

// Apple IIe-specific pattern detector
class AppleIIePatternDetector : public PatternDetector {
 public:
  AppleIIePatternDetector();

  void AnalyzePatterns(
      const std::vector<core::Instruction>& instructions,
      core::AddressMap* address_map,
      const core::SymbolTable* symbol_table = nullptr) override;

  std::string GetPlatformName() const override { return "apple2e"; }

 private:
  void InitializeHardwareRegisters();

  // Apple II soft switches have simpler patterns (read/write to toggle)
  bool DetectSoftSwitchAccess(
      const std::vector<core::Instruction>& instructions,
      size_t index,
      DetectedPattern* pattern) const;
};

// Factory function
std::unique_ptr<PatternDetector> CreatePatternDetector(
    const std::string& platform);

}  // namespace analysis
}  // namespace sourcerer

#endif  // SOURCERER_ANALYSIS_PATTERN_DETECTOR_H_
