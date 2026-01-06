// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "analysis/pattern_detector.h"

#include <sstream>

#include "core/symbol_table.h"
#include "utils/logger.h"

namespace sourcerer {
namespace analysis {

// Base class helpers

bool PatternDetector::IsHardwareRegister(uint32_t address) const {
  return hardware_registers_.find(address) != hardware_registers_.end();
}

const HardwareRegister* PatternDetector::GetRegister(uint32_t address) const {
  auto it = hardware_registers_.find(address);
  if (it != hardware_registers_.end()) {
    return &it->second;
  }
  return nullptr;
}

std::string PatternDetector::DecodeBitMask(uint32_t register_addr,
                                           uint8_t mask) const {
  const HardwareRegister* reg = GetRegister(register_addr);
  if (!reg) {
    return "";
  }

  std::vector<std::string> bit_names;

  // Check each bit in the mask
  for (uint8_t bit = 0; bit < 8; ++bit) {
    if (mask & (1 << bit)) {
      auto it = reg->bit_map.find(bit);
      if (it != reg->bit_map.end()) {
        bit_names.push_back(it->second->description);
      }
    }
  }

  // Combine bit names
  if (bit_names.empty()) {
    return "";
  } else if (bit_names.size() == 1) {
    return bit_names[0];
  } else {
    std::ostringstream oss;
    for (size_t i = 0; i < bit_names.size(); ++i) {
      if (i > 0) oss << ", ";
      oss << bit_names[i];
    }
    return oss.str();
  }
}

// CoCo Pattern Detector

CoCoPatternDetector::CoCoPatternDetector() {
  InitializeHardwareRegisters();
}

void CoCoPatternDetector::InitializeHardwareRegisters() {
  // PIA0 Control Register A - $FF01
  {
    HardwareRegister reg;
    reg.address = 0xFF01;
    reg.name = "PIA0_CA";
    reg.description = "PIA0 Control A";

    BitField irq_enable;
    irq_enable.bit_number = 0;
    irq_enable.name = "IRQ_ENABLE";
    irq_enable.description = "keyboard IRQ";
    reg.bits.push_back(irq_enable);

    hardware_registers_[0xFF01] = reg;
    // Build bit_map after insertion to avoid pointer invalidation
    hardware_registers_[0xFF01].bit_map[0] = &hardware_registers_[0xFF01].bits[0];
  }

  // PIA0 Control Register B - $FF03
  {
    HardwareRegister reg;
    reg.address = 0xFF03;
    reg.name = "PIA0_CB";
    reg.description = "PIA0 Control B";

    BitField irq_enable;
    irq_enable.bit_number = 0;
    irq_enable.name = "IRQ_ENABLE";
    irq_enable.description = "IRQ";
    reg.bits.push_back(irq_enable);

    BitField motor;
    motor.bit_number = 3;
    motor.name = "MOTOR";
    motor.description = "cassette motor";
    reg.bits.push_back(motor);

    hardware_registers_[0xFF03] = reg;
    // Build bit_map after insertion
    hardware_registers_[0xFF03].bit_map[0] = &hardware_registers_[0xFF03].bits[0];
    hardware_registers_[0xFF03].bit_map[3] = &hardware_registers_[0xFF03].bits[1];
  }

  // PIA1 Data Register A - $FF20
  {
    HardwareRegister reg;
    reg.address = 0xFF20;
    reg.name = "PIA1_DA";
    reg.description = "PIA1 Data A";

    BitField dac;
    dac.bit_number = 2;  // Bits 2-7 are DAC
    dac.name = "DAC";
    dac.description = "6-bit DAC (sound)";
    reg.bits.push_back(dac);

    hardware_registers_[0xFF20] = reg;
    // Mark bits 2-7 as DAC
    for (uint8_t b = 2; b <= 7; ++b) {
      hardware_registers_[0xFF20].bit_map[b] = &hardware_registers_[0xFF20].bits[0];
    }
  }

  // PIA1 Control Register A - $FF21
  {
    HardwareRegister reg;
    reg.address = 0xFF21;
    reg.name = "PIA1_CA";
    reg.description = "PIA1 Control A";

    BitField irq_enable;
    irq_enable.bit_number = 0;
    irq_enable.name = "IRQ_ENABLE";
    irq_enable.description = "HSYNC IRQ";
    reg.bits.push_back(irq_enable);

    hardware_registers_[0xFF21] = reg;
    hardware_registers_[0xFF21].bit_map[0] = &hardware_registers_[0xFF21].bits[0];
  }

  // PIA1 Data Register B - $FF22
  {
    HardwareRegister reg;
    reg.address = 0xFF22;
    reg.name = "PIA1_DB";
    reg.description = "PIA1 Data B";

    BitField vdg_mode;
    vdg_mode.bit_number = 2;  // Bits 2-4 are VDG mode
    vdg_mode.name = "VDG_MODE";
    vdg_mode.description = "VDG mode";
    reg.bits.push_back(vdg_mode);

    BitField sound;
    sound.bit_number = 6;
    sound.name = "SOUND";
    sound.description = "1-bit sound";
    reg.bits.push_back(sound);

    hardware_registers_[0xFF22] = reg;
    for (uint8_t b = 2; b <= 4; ++b) {
      hardware_registers_[0xFF22].bit_map[b] = &hardware_registers_[0xFF22].bits[0];
    }
    hardware_registers_[0xFF22].bit_map[6] = &hardware_registers_[0xFF22].bits[1];
  }

  // PIA1 Control Register B - $FF23
  {
    HardwareRegister reg;
    reg.address = 0xFF23;
    reg.name = "PIA1_CB";
    reg.description = "PIA1 Control B";

    BitField irq_enable;
    irq_enable.bit_number = 0;
    irq_enable.name = "IRQ_ENABLE";
    irq_enable.description = "VSYNC IRQ";
    reg.bits.push_back(irq_enable);

    hardware_registers_[0xFF23] = reg;
    hardware_registers_[0xFF23].bit_map[0] = &hardware_registers_[0xFF23].bits[0];
  }
}

void CoCoPatternDetector::AnalyzePatterns(
    const std::vector<core::Instruction>& instructions,
    core::AddressMap* address_map,
    const core::SymbolTable* symbol_table) {
  (void)symbol_table;  // Unused in CoCo pattern detection

  LOG_INFO("Running CoCo pattern detection...");
  int patterns_found = 0;

  for (size_t i = 0; i < instructions.size(); ++i) {
    DetectedPattern pattern;

    // Try to detect various patterns
    if (DetectSetBitPattern(instructions, i, &pattern) ||
        DetectClearBitPattern(instructions, i, &pattern) ||
        DetectToggleBitPattern(instructions, i, &pattern) ||
        DetectWriteValuePattern(instructions, i, &pattern)) {

      // Add comment to the final instruction in the pattern
      if (!pattern.comment.empty()) {
        address_map->SetComment(pattern.end_address, pattern.comment);
        patterns_found++;
      }
    }
  }

  LOG_INFO("CoCo pattern detection complete: " +
           std::to_string(patterns_found) + " pattern(s) found");
}

bool CoCoPatternDetector::DetectSetBitPattern(
    const std::vector<core::Instruction>& instructions,
    size_t index,
    DetectedPattern* pattern) const {

  // Pattern: LDA $FFxx / ORA #$xx / STA $FFxx
  if (index + 2 >= instructions.size()) {
    return false;
  }

  const auto& inst1 = instructions[index];
  const auto& inst2 = instructions[index + 1];
  const auto& inst3 = instructions[index + 2];

  // Check instruction sequence
  if (inst1.mnemonic != "LDA" || inst2.mnemonic != "ORA" ||
      inst3.mnemonic != "STA") {
    return false;
  }

  // Extract addresses from operands (handle both target_address and operand string)
  auto extract_address = [](const core::Instruction& inst) -> uint32_t {
    if (inst.target_address != 0) {
      return inst.target_address;
    }
    // Try to parse from operand string
    if (inst.operand.find('$') != std::string::npos) {
      try {
        size_t dollar_pos = inst.operand.find('$');
        std::string addr_str = inst.operand.substr(dollar_pos + 1);
        // Remove anything after comma or space
        size_t end_pos = addr_str.find_first_of(", ");
        if (end_pos != std::string::npos) {
          addr_str = addr_str.substr(0, end_pos);
        }
        return std::stoul(addr_str, nullptr, 16);
      } catch (...) {
        return 0;
      }
    }
    return 0;
  };

  uint32_t addr1 = extract_address(inst1);
  uint32_t addr3 = extract_address(inst3);

  // inst1 and inst3 must target the same hardware register
  if (addr1 == 0 || addr3 == 0 || addr1 != addr3) {
    return false;
  }

  uint32_t reg_addr = addr1;

  // Must be a hardware register we know about
  if (!IsHardwareRegister(reg_addr)) {
    return false;
  }

  // inst2 must be immediate mode (ORA #$xx)
  if (inst2.operand.find('#') == std::string::npos) {
    return false;
  }

  // Extract bit mask from ORA immediate value
  uint8_t mask = 0;
  try {
    std::string operand = inst2.operand;
    size_t hash_pos = operand.find('#');
    if (hash_pos != std::string::npos) {
      operand = operand.substr(hash_pos + 1);
    }
    if (operand[0] == '$') {
      mask = std::stoul(operand.substr(1), nullptr, 16);
    } else {
      mask = std::stoul(operand, nullptr, 0);
    }
  } catch (...) {
    return false;
  }

  // Decode the bit mask
  std::string bit_desc = DecodeBitMask(reg_addr, mask);

  // Build comment
  pattern->type = PatternType::SET_BIT;
  pattern->start_address = inst1.address;
  pattern->end_address = inst3.address;
  pattern->target_register = reg_addr;
  pattern->bit_mask = mask;

  if (!bit_desc.empty()) {
    pattern->comment = "Enable " + bit_desc;
  } else {
    std::ostringstream oss;
    oss << "Set bit(s) $" << std::hex << std::uppercase
        << static_cast<int>(mask);
    pattern->comment = oss.str();
  }

  return true;
}

bool CoCoPatternDetector::DetectClearBitPattern(
    const std::vector<core::Instruction>& instructions,
    size_t index,
    DetectedPattern* pattern) const {

  // Pattern: LDA $FFxx / ANDA #$xx / STA $FFxx
  if (index + 2 >= instructions.size()) {
    return false;
  }

  const auto& inst1 = instructions[index];
  const auto& inst2 = instructions[index + 1];
  const auto& inst3 = instructions[index + 2];

  // Check instruction sequence
  if (inst1.mnemonic != "LDA" || inst2.mnemonic != "ANDA" ||
      inst3.mnemonic != "STA") {
    return false;
  }

  // Extract addresses from operands
  auto extract_address = [](const core::Instruction& inst) -> uint32_t {
    if (inst.target_address != 0) {
      return inst.target_address;
    }
    if (inst.operand.find('$') != std::string::npos) {
      try {
        size_t dollar_pos = inst.operand.find('$');
        std::string addr_str = inst.operand.substr(dollar_pos + 1);
        size_t end_pos = addr_str.find_first_of(", ");
        if (end_pos != std::string::npos) {
          addr_str = addr_str.substr(0, end_pos);
        }
        return std::stoul(addr_str, nullptr, 16);
      } catch (...) {
        return 0;
      }
    }
    return 0;
  };

  uint32_t addr1 = extract_address(inst1);
  uint32_t addr3 = extract_address(inst3);

  // inst1 and inst3 must target the same hardware register
  if (addr1 == 0 || addr3 == 0 || addr1 != addr3) {
    return false;
  }

  uint32_t reg_addr = addr1;

  // Must be a hardware register we know about
  if (!IsHardwareRegister(reg_addr)) {
    return false;
  }

  // inst2 must be immediate mode (ANDA #$xx)
  if (inst2.operand.find('#') == std::string::npos) {
    return false;
  }

  // Extract bit mask from ANDA immediate value
  uint8_t mask = 0;
  try {
    std::string operand = inst2.operand;
    size_t hash_pos = operand.find('#');
    if (hash_pos != std::string::npos) {
      operand = operand.substr(hash_pos + 1);
    }
    if (operand[0] == '$') {
      mask = std::stoul(operand.substr(1), nullptr, 16);
    } else {
      mask = std::stoul(operand, nullptr, 0);
    }
  } catch (...) {
    return false;
  }

  // Invert mask to get bits being cleared
  uint8_t cleared_bits = ~mask;

  // Decode the bit mask
  std::string bit_desc = DecodeBitMask(reg_addr, cleared_bits);

  // Build comment
  pattern->type = PatternType::CLEAR_BIT;
  pattern->start_address = inst1.address;
  pattern->end_address = inst3.address;
  pattern->target_register = reg_addr;
  pattern->bit_mask = cleared_bits;

  if (!bit_desc.empty()) {
    pattern->comment = "Disable " + bit_desc;
  } else {
    std::ostringstream oss;
    oss << "Clear bit(s) $" << std::hex << std::uppercase
        << static_cast<int>(cleared_bits);
    pattern->comment = oss.str();
  }

  return true;
}

bool CoCoPatternDetector::DetectToggleBitPattern(
    const std::vector<core::Instruction>& instructions,
    size_t index,
    DetectedPattern* pattern) const {

  // Pattern: LDA $FFxx / EORA #$xx / STA $FFxx
  if (index + 2 >= instructions.size()) {
    return false;
  }

  const auto& inst1 = instructions[index];
  const auto& inst2 = instructions[index + 1];
  const auto& inst3 = instructions[index + 2];

  // Check instruction sequence
  if (inst1.mnemonic != "LDA" || inst2.mnemonic != "EORA" ||
      inst3.mnemonic != "STA") {
    return false;
  }

  // Extract addresses from operands
  auto extract_address = [](const core::Instruction& inst) -> uint32_t {
    if (inst.target_address != 0) {
      return inst.target_address;
    }
    if (inst.operand.find('$') != std::string::npos) {
      try {
        size_t dollar_pos = inst.operand.find('$');
        std::string addr_str = inst.operand.substr(dollar_pos + 1);
        size_t end_pos = addr_str.find_first_of(", ");
        if (end_pos != std::string::npos) {
          addr_str = addr_str.substr(0, end_pos);
        }
        return std::stoul(addr_str, nullptr, 16);
      } catch (...) {
        return 0;
      }
    }
    return 0;
  };

  uint32_t addr1 = extract_address(inst1);
  uint32_t addr3 = extract_address(inst3);

  // inst1 and inst3 must target the same hardware register
  if (addr1 == 0 || addr3 == 0 || addr1 != addr3) {
    return false;
  }

  uint32_t reg_addr = addr1;

  // Must be a hardware register we know about
  if (!IsHardwareRegister(reg_addr)) {
    return false;
  }

  // inst2 must be immediate mode (EORA #$xx)
  if (inst2.operand.find('#') == std::string::npos) {
    return false;
  }

  // Extract bit mask from EORA immediate value
  uint8_t mask = 0;
  try {
    std::string operand = inst2.operand;
    size_t hash_pos = operand.find('#');
    if (hash_pos != std::string::npos) {
      operand = operand.substr(hash_pos + 1);
    }
    if (operand[0] == '$') {
      mask = std::stoul(operand.substr(1), nullptr, 16);
    } else {
      mask = std::stoul(operand, nullptr, 0);
    }
  } catch (...) {
    return false;
  }

  // Decode the bit mask
  std::string bit_desc = DecodeBitMask(reg_addr, mask);

  // Build comment
  pattern->type = PatternType::TOGGLE_BIT;
  pattern->start_address = inst1.address;
  pattern->end_address = inst3.address;
  pattern->target_register = reg_addr;
  pattern->bit_mask = mask;

  if (!bit_desc.empty()) {
    pattern->comment = "Toggle " + bit_desc;
  } else {
    std::ostringstream oss;
    oss << "Toggle bit(s) $" << std::hex << std::uppercase
        << static_cast<int>(mask);
    pattern->comment = oss.str();
  }

  return true;
}

bool CoCoPatternDetector::DetectWriteValuePattern(
    const std::vector<core::Instruction>& instructions,
    size_t index,
    DetectedPattern* pattern) const {

  // Pattern: LDA #$xx / STA $FFxx
  if (index + 1 >= instructions.size()) {
    return false;
  }

  const auto& inst1 = instructions[index];
  const auto& inst2 = instructions[index + 1];

  // Check instruction sequence
  if (inst1.mnemonic != "LDA" || inst2.mnemonic != "STA") {
    return false;
  }

  // inst1 must be immediate mode
  if (inst1.operand.find('#') == std::string::npos) {
    return false;
  }

  // Extract address from operand
  auto extract_address = [](const core::Instruction& inst) -> uint32_t {
    if (inst.target_address != 0) {
      return inst.target_address;
    }
    if (inst.operand.find('$') != std::string::npos) {
      try {
        size_t dollar_pos = inst.operand.find('$');
        std::string addr_str = inst.operand.substr(dollar_pos + 1);
        size_t end_pos = addr_str.find_first_of(", ");
        if (end_pos != std::string::npos) {
          addr_str = addr_str.substr(0, end_pos);
        }
        return std::stoul(addr_str, nullptr, 16);
      } catch (...) {
        return 0;
      }
    }
    return 0;
  };

  uint32_t reg_addr = extract_address(inst2);

  // inst2 must target a hardware register
  if (reg_addr == 0) {
    return false;
  }

  // Must be a hardware register we know about
  if (!IsHardwareRegister(reg_addr)) {
    return false;
  }

  // Extract value being written
  uint8_t value = 0;
  try {
    std::string operand = inst1.operand;
    size_t hash_pos = operand.find('#');
    if (hash_pos != std::string::npos) {
      operand = operand.substr(hash_pos + 1);
    }
    if (operand[0] == '$') {
      value = std::stoul(operand.substr(1), nullptr, 16);
    } else {
      value = std::stoul(operand, nullptr, 0);
    }
  } catch (...) {
    return false;
  }

  // Build comment based on register and value
  pattern->type = PatternType::WRITE_VALUE;
  pattern->start_address = inst1.address;
  pattern->end_address = inst2.address;
  pattern->target_register = reg_addr;
  pattern->bit_mask = value;

  const HardwareRegister* reg = GetRegister(reg_addr);
  if (reg) {
    std::ostringstream oss;
    oss << "Write $" << std::hex << std::uppercase << static_cast<int>(value)
        << " to " << reg->description;
    pattern->comment = oss.str();
  }

  return true;
}

// Apple IIe Pattern Detector

AppleIIePatternDetector::AppleIIePatternDetector() {
  InitializeHardwareRegisters();
}

void AppleIIePatternDetector::InitializeHardwareRegisters() {
  // Graphics/Text Mode Soft Switches ($C050-$C057)
  {
    HardwareRegister reg;
    reg.address = 0xC050;
    reg.name = "TEXTOFF";
    reg.description = "Select graphics mode";
    hardware_registers_[0xC050] = reg;
  }
  {
    HardwareRegister reg;
    reg.address = 0xC051;
    reg.name = "TEXTON";
    reg.description = "Select text mode";
    hardware_registers_[0xC051] = reg;
  }
  {
    HardwareRegister reg;
    reg.address = 0xC052;
    reg.name = "MIXEDOFF";
    reg.description = "Full-screen graphics";
    hardware_registers_[0xC052] = reg;
  }
  {
    HardwareRegister reg;
    reg.address = 0xC053;
    reg.name = "MIXEDON";
    reg.description = "Graphics with 4 lines of text";
    hardware_registers_[0xC053] = reg;
  }
  {
    HardwareRegister reg;
    reg.address = 0xC054;
    reg.name = "PAGE2OFF";
    reg.description = "Select page 1 display";
    hardware_registers_[0xC054] = reg;
  }
  {
    HardwareRegister reg;
    reg.address = 0xC055;
    reg.name = "PAGE2ON";
    reg.description = "Select page 2 display";
    hardware_registers_[0xC055] = reg;
  }
  {
    HardwareRegister reg;
    reg.address = 0xC056;
    reg.name = "HIRESOFF";
    reg.description = "Select low-resolution graphics";
    hardware_registers_[0xC056] = reg;
  }
  {
    HardwareRegister reg;
    reg.address = 0xC057;
    reg.name = "HIRESON";
    reg.description = "Select high-resolution graphics";
    hardware_registers_[0xC057] = reg;
  }

  // Keyboard I/O
  {
    HardwareRegister reg;
    reg.address = 0xC000;
    reg.name = "KBD";
    reg.description = "Keyboard data";
    hardware_registers_[0xC000] = reg;
  }
  {
    HardwareRegister reg;
    reg.address = 0xC010;
    reg.name = "KBDSTRB";
    reg.description = "Clear keyboard strobe";
    hardware_registers_[0xC010] = reg;
  }

  // 80-column switches
  {
    HardwareRegister reg;
    reg.address = 0xC000;
    reg.name = "80STOREOFF";
    reg.description = "PAGE2 switches video pages";
    hardware_registers_[0xC000] = reg;
  }
  {
    HardwareRegister reg;
    reg.address = 0xC001;
    reg.name = "80STOREON";
    reg.description = "PAGE2 switches main/aux memory";
    hardware_registers_[0xC001] = reg;
  }

  // Speaker
  {
    HardwareRegister reg;
    reg.address = 0xC030;
    reg.name = "SPEAKER";
    reg.description = "Toggle speaker";
    hardware_registers_[0xC030] = reg;
  }
}

void AppleIIePatternDetector::AnalyzePatterns(
    const std::vector<core::Instruction>& instructions,
    core::AddressMap* address_map,
    const core::SymbolTable* symbol_table) {
  (void)symbol_table;  // Unused in Apple IIe pattern detection

  LOG_INFO("Running Apple IIe pattern detection...");
  int patterns_found = 0;

  for (size_t i = 0; i < instructions.size(); ++i) {
    DetectedPattern pattern;

    // Detect soft switch access
    if (DetectSoftSwitchAccess(instructions, i, &pattern)) {
      // Add comment to the instruction
      if (!pattern.comment.empty()) {
        address_map->SetComment(pattern.end_address, pattern.comment);
        patterns_found++;
      }
    }
  }

  LOG_INFO("Apple IIe pattern detection complete: " +
           std::to_string(patterns_found) + " pattern(s) found");
}

bool AppleIIePatternDetector::DetectSoftSwitchAccess(
    const std::vector<core::Instruction>& instructions,
    size_t index,
    DetectedPattern* pattern) const {

  if (index >= instructions.size()) {
    return false;
  }

  const auto& inst = instructions[index];

  // Check for LDA, STA, LDX, STX, etc. accessing soft switches
  bool is_load_or_store = (inst.mnemonic == "LDA" || inst.mnemonic == "STA" ||
                           inst.mnemonic == "LDX" || inst.mnemonic == "STX" ||
                           inst.mnemonic == "LDY" || inst.mnemonic == "STY" ||
                           inst.mnemonic == "BIT");

  if (!is_load_or_store) {
    return false;
  }

  // Extract address from operand
  auto extract_address = [](const core::Instruction& inst) -> uint32_t {
    if (inst.target_address != 0) {
      return inst.target_address;
    }
    if (inst.operand.find('$') != std::string::npos) {
      try {
        size_t dollar_pos = inst.operand.find('$');
        std::string addr_str = inst.operand.substr(dollar_pos + 1);
        size_t end_pos = addr_str.find_first_of(", ");
        if (end_pos != std::string::npos) {
          addr_str = addr_str.substr(0, end_pos);
        }
        return std::stoul(addr_str, nullptr, 16);
      } catch (...) {
        return 0;
      }
    }
    return 0;
  };

  uint32_t addr = extract_address(inst);
  if (addr == 0) {
    return false;
  }

  // Check if it's a known soft switch
  const HardwareRegister* reg = GetRegister(addr);
  if (!reg) {
    return false;
  }

  // Build comment
  pattern->type = PatternType::WRITE_VALUE;
  pattern->start_address = inst.address;
  pattern->end_address = inst.address;
  pattern->target_register = addr;
  pattern->bit_mask = 0;
  pattern->comment = reg->description;

  return true;
}

// Factory function

std::unique_ptr<PatternDetector> CreatePatternDetector(
    const std::string& platform) {
  if (platform == "coco") {
    return std::make_unique<CoCoPatternDetector>();
  } else if (platform == "apple2" || platform == "apple2e") {
    return std::make_unique<AppleIIePatternDetector>();
  }
  return nullptr;
}

}  // namespace analysis
}  // namespace sourcerer
