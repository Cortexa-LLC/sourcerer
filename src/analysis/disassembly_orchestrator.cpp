// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "analysis/disassembly_orchestrator.h"

#include <set>

#include "analysis/code_analyzer.h"
#include "utils/logger.h"

namespace sourcerer {
namespace analysis {

DisassemblyOrchestrator::DisassemblyOrchestrator(cpu::CpuPlugin* cpu,
                                                 const core::Binary* binary)
    : cpu_(cpu), binary_(binary) {}

std::vector<core::Instruction>
DisassemblyOrchestrator::DisassembleWithAnalysis(
    core::AddressMap* address_map,
    uint32_t entry_point,
    const core::SymbolTable* symbol_table) {

  std::vector<core::Instruction> instructions;

  // Run code flow analysis
  LOG_INFO("Running code flow analysis...");
  CodeAnalyzer analyzer(cpu_, binary_);

  // Add primary entry point (use specified or default to load address)
  uint32_t ep;
  if (entry_point != 0) {
    // User specified explicit entry point
    ep = entry_point;
    analyzer.AddEntryPoint(ep);
    LOG_INFO("Entry point: $" + std::to_string(ep));
  } else {
    // Auto-detect entry point (skips ROM headers if needed)
    ep = analyzer.FindFirstValidInstruction(binary_->load_address());
    analyzer.AddEntryPoint(ep);
    if (ep != binary_->load_address()) {
      LOG_INFO("Skipped " + std::to_string(ep - binary_->load_address()) +
               " byte(s) of non-code data at start of binary");
    }
    LOG_INFO("Entry point: $" + std::to_string(ep));
  }

  // Add ROM_ROUTINE symbols as additional entry points (with validation)
  if (symbol_table) {
    int symbol_entry_points = 0;
    int rejected_symbols = 0;
    const auto& symbols = symbol_table->GetAllSymbols();
    for (const auto& pair : symbols) {
      const auto& symbol = pair.second;
      // Only add ROM_ROUTINE symbols within the binary range as entry points
      if (symbol.type == core::SymbolType::ROM_ROUTINE &&
          symbol.address >= binary_->load_address() &&
          symbol.address < binary_->load_address() + binary_->size()) {

        // Validate: check if address contains a valid (non-illegal) instruction
        const uint8_t* data = binary_->GetPointer(symbol.address);
        size_t remaining = binary_->size() - (symbol.address - binary_->load_address());
        if (data && remaining > 0) {
          try {
            core::Instruction test_inst = cpu_->Disassemble(data, remaining, symbol.address);
            // Only add if it's a valid, non-illegal instruction
            if (!test_inst.is_illegal && !test_inst.bytes.empty()) {
              analyzer.AddEntryPoint(symbol.address);
              symbol_entry_points++;
              LOG_DEBUG("Added symbol entry point: " + symbol.name + " at $" +
                        std::to_string(symbol.address));
            } else {
              rejected_symbols++;
              LOG_DEBUG("Rejected symbol (illegal opcode): " + symbol.name + " at $" +
                        std::to_string(symbol.address));
            }
          } catch (const std::exception& e) {
            rejected_symbols++;
            LOG_DEBUG("Rejected symbol (disassembly failed): " + symbol.name + " at $" +
                      std::to_string(symbol.address) + ": " + e.what());
          }
        }
      }
    }
    if (symbol_entry_points > 0) {
      LOG_INFO("Added " + std::to_string(symbol_entry_points) +
               " ROM routine symbols as entry points");
    }
    if (rejected_symbols > 0) {
      LOG_INFO("Rejected " + std::to_string(rejected_symbols) +
               " ROM symbols (illegal opcodes or data)");
    }
  }

  // Analyze using recursive multi-pass analysis
  analyzer.RecursiveAnalyze(address_map);

  // Now disassemble only the code regions
  uint32_t address = binary_->load_address();
  uint32_t end_address = address + binary_->size();

  LOG_INFO("Disassembling code regions...");

  // Build a set of all instruction start addresses from the analyzer's instruction cache
  // This helps us identify instruction boundaries vs mid-instruction bytes
  std::set<uint32_t> instruction_boundaries;

  // Scan CODE regions to find instruction boundaries
  for (uint32_t addr = binary_->load_address(); addr < end_address; ) {
    if (!address_map->IsCode(addr)) {
      addr++;
      continue;
    }

    // This is a CODE address - try to disassemble to find instruction start
    const uint8_t* data = binary_->GetPointer(addr);
    size_t remaining = end_address - addr;

    if (!data || remaining == 0) {
      addr++;
      continue;
    }

    try {
      core::Instruction inst = cpu_->Disassemble(data, remaining, addr);

      if (!inst.is_illegal && !inst.bytes.empty()) {
        // Check if all bytes of this instruction are marked as CODE
        bool all_bytes_are_code = true;
        for (size_t i = 0; i < inst.bytes.size(); ++i) {
          if (!address_map->IsCode(addr + i)) {
            all_bytes_are_code = false;
            break;
          }
        }

        if (all_bytes_are_code) {
          // This is a valid instruction boundary
          instruction_boundaries.insert(addr);

          // CRITICAL: Increment by 1, not inst.bytes.size()!
          // This ensures we check EVERY CODE address, including those in the middle
          // of overlapping instructions (resolved misalignments)
          addr++;
        } else {
          // Partial CODE marking - skip this address
          addr++;
        }
      } else {
        addr++;
      }
    } catch (const std::exception& e) {
      LOG_DEBUG("Disassembly failed at $" + std::to_string(addr) +
                " during boundary detection: " + e.what());
      addr++;
    }
  }

  LOG_DEBUG("Found " + std::to_string(instruction_boundaries.size()) +
            " instruction boundaries");

  // Now disassemble all instructions at boundaries
  for (uint32_t addr : instruction_boundaries) {
    const uint8_t* data = binary_->GetPointer(addr);
    size_t remaining = end_address - addr;

    if (!data || remaining == 0) {
      continue;
    }

    try {
      core::Instruction inst = cpu_->Disassemble(data, remaining, addr);

      if (!inst.is_illegal && !inst.bytes.empty()) {
        instructions.push_back(inst);
      }
    } catch (const std::exception& e) {
      LOG_ERROR("Disassembly failed at $" + std::to_string(addr) +
                ": " + e.what());
    }
  }

  LOG_INFO("Disassembled " + std::to_string(instructions.size()) +
           " instructions from code regions");
  return instructions;
}

std::vector<core::Instruction> DisassemblyOrchestrator::DisassembleLinear() {
  std::vector<core::Instruction> instructions;

  uint32_t address = binary_->load_address();
  uint32_t end_address = address + binary_->size();

  LOG_INFO("Linear disassembly from $" +
           std::to_string(address) + " to $" +
           std::to_string(end_address));

  while (address < end_address) {
    const uint8_t* data = binary_->GetPointer(address);
    size_t remaining = end_address - address;

    if (!data || remaining == 0) {
      break;
    }

    try {
      core::Instruction inst = cpu_->Disassemble(data, remaining, address);
      instructions.push_back(inst);

      // Move to next instruction
      address += inst.bytes.size();

      // Stop at RTS/RTI/BRK in linear mode
      if (inst.is_return) {
        LOG_DEBUG("Encountered return instruction at $" +
                 std::to_string(inst.address));
        break;
      }

    } catch (const std::exception& e) {
      LOG_ERROR("Disassembly failed at $" + std::to_string(address) +
                ": " + e.what());
      break;
    }
  }

  LOG_INFO("Disassembled " + std::to_string(instructions.size()) + " instructions");
  return instructions;
}

}  // namespace analysis
}  // namespace sourcerer
