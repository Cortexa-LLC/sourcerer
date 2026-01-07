// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "analysis/strategies/inline_data_scanner.h"

#include <iomanip>
#include <sstream>

#include "utils/logger.h"

namespace sourcerer {
namespace analysis {

InlineDataScanner::InlineDataScanner(cpu::CpuPlugin* cpu,
                                     const core::Binary* binary,
                                     const core::PlatformHints* hints)
    : cpu_(cpu), binary_(binary), hints_(hints) {
  // Register inline data routines from platform hints
  if (hints_) {
    // Hints will be queried dynamically via IsInlineDataRoutine()
    LOG_DEBUG("InlineDataScanner initialized with platform hints");
  } else {
    // Fallback: register known platform-specific inline data routines
    // ProDOS MLI: JSR $BF00 followed by 1 byte (command) + 2 bytes (param pointer)
    known_inline_data_routines_[0xBF00] = 3;
    LOG_DEBUG("InlineDataScanner initialized with hard-coded routines");
  }
}

bool InlineDataScanner::IsValidAddress(uint32_t address) const {
  uint32_t start = binary_->load_address();
  uint32_t end = start + binary_->size();
  return address >= start && address < end;
}

void InlineDataScanner::RegisterKnownRoutine(uint32_t address,
                                             size_t bytes_after_call) {
  known_inline_data_routines_[address] = bytes_after_call;
  LOG_DEBUG("Registered inline data routine at $" + std::to_string(address) +
            " with " + std::to_string(bytes_after_call) + " bytes");
}

bool InlineDataScanner::IsKnownRoutine(uint32_t address,
                                       size_t* bytes_after_call) const {
  // Check platform hints first
  if (hints_ && hints_->IsInlineDataRoutine(address, bytes_after_call)) {
    return true;
  }

  // Fall back to hard-coded routines
  auto it = known_inline_data_routines_.find(address);
  if (it != known_inline_data_routines_.end()) {
    if (bytes_after_call) {
      *bytes_after_call = it->second;
    }
    return true;
  }
  return false;
}

bool InlineDataScanner::IsInlineDataRoutine(uint32_t address,
                                            core::AddressMap* address_map) {
  (void)address_map;  // Reserved for future use

  // Check if we've already identified this routine
  if (inline_data_routines_.count(address) > 0) {
    return true;
  }

  // Scan first few instructions of subroutine for inline data pattern:
  // Pattern: PLA, STA/STX/STY (save return address), ... read data ...,
  //          LDA/LDX/LDY, PHA (restore adjusted return address), RTS

  if (!IsValidAddress(address)) {
    return false;
  }

  try {
    const uint8_t* data = binary_->GetPointer(address);
    size_t remaining = binary_->load_address() + binary_->size() - address;

    // Check first instruction - should pull return address (PLA or TSX)
    core::Instruction inst1 = cpu_->Disassemble(data, remaining, address);
    if (inst1.mnemonic != "PLA" && inst1.mnemonic != "TSX") {
      return false;
    }

    // If we see PLA at start, it's likely an inline data routine
    // Add to our tracking set
    inline_data_routines_.insert(address);
    LOG_DEBUG("Detected inline data routine at $" + std::to_string(address));
    return true;

  } catch (const std::exception&) {
    return false;
  }
}

uint32_t InlineDataScanner::ScanInlineData(uint32_t start_address,
                                           core::AddressMap* address_map,
                                           int* data_bytes_counter) {
  // Scan forward from start_address to find data terminator (usually $00)
  // Mark encountered bytes as data
  // Return address after terminator

  uint32_t addr = start_address;
  size_t count = 0;

  while (IsValidAddress(addr) && count < kMaxInlineDataSize) {
    const uint8_t* data = binary_->GetPointer(addr);
    if (!data) break;

    uint8_t byte = *data;

    // Mark as data
    if (!address_map->IsCode(addr)) {
      address_map->SetType(addr, core::AddressType::INLINE_DATA);
      if (data_bytes_counter) {
        (*data_bytes_counter)++;
      }
    }

    // Check for terminator (0x00)
    if (byte == 0x00) {
      LOG_DEBUG("Found inline data: $" + std::to_string(start_address) +
                " to $" + std::to_string(addr) + " (" +
                std::to_string(count + 1) + " bytes)");
      return addr + 1;  // Return address after terminator
    }

    addr++;
    count++;
  }

  LOG_WARNING("No terminator found for inline data at $" +
              std::to_string(start_address));
  return 0;  // No valid terminator found
}

int InlineDataScanner::ScanAndMarkInlineData(
    const std::vector<core::Instruction>& instructions,
    core::AddressMap* address_map,
    const core::SymbolTable* symbol_table) {
  int marked_count = 0;

  for (const auto& inst : instructions) {
    // Check if this is a call to a known inline data routine
    if (inst.is_call && inst.target_address != 0) {
      size_t inline_bytes = 0;
      if (IsKnownRoutine(inst.target_address, &inline_bytes)) {
        // Mark next N bytes after the JSR as INLINE_DATA
        uint32_t data_addr = inst.address + inst.bytes.size();

        // Build comment(s) for inline data
        std::string comment;
        std::vector<std::string> parameter_comments;

        // Try platform hints first (preferred method)
        if (hints_ && inline_bytes >= 1 && IsValidAddress(data_addr)) {
          const uint8_t* call_byte = binary_->GetPointer(data_addr);
          if (call_byte) {
            uint32_t call_num = *call_byte;
            // Look up the MLI call name from hints
            auto call_info = hints_->GetMliCallInfo(call_num);
            if (call_info.has_value()) {
              // Generate header comment
              std::ostringstream header;
              header << "MLI " << call_info->name << " ($"
                     << std::hex << std::uppercase << call_num << ")";
              if (!call_info->description.empty()) {
                header << " - " << call_info->description;
              }
              comment = header.str();

              // Generate parameter structure comments if available
              if (!call_info->parameters.empty()) {
                // Read parameter pointer from inline data (bytes 2-3)
                if (inline_bytes >= 3 && IsValidAddress(data_addr + 1)) {
                  const uint8_t* ptr_bytes = binary_->GetPointer(data_addr + 1);
                  if (ptr_bytes) {
                    // Little-endian address
                    uint16_t param_addr = ptr_bytes[0] | (ptr_bytes[1] << 8);

                    std::ostringstream addr_str;
                    addr_str << "Parameter block at $"
                            << std::hex << std::uppercase << std::setfill('0')
                            << std::setw(4) << param_addr << ":";
                    parameter_comments.push_back(addr_str.str());

                    // Document each parameter
                    for (const auto& param : call_info->parameters) {
                      std::ostringstream param_line;
                      param_line << "  +" << std::dec << param.offset
                                << " (" << param.size << "): " << param.name;
                      if (!param.description.empty()) {
                        param_line << " - " << param.description;
                      }
                      parameter_comments.push_back(param_line.str());
                    }
                  }
                }
              }
            }
          }
        }

        // Fall back to symbol table if no hints
        if (comment.empty() && symbol_table) {
          auto symbol = symbol_table->GetSymbol(inst.target_address);
          if (symbol && symbol->type == core::SymbolType::ROM_ROUTINE) {
            // This is MLI or similar - read the first byte to identify the call
            if (inline_bytes >= 1 && IsValidAddress(data_addr)) {
              const uint8_t* call_byte = binary_->GetPointer(data_addr);
              if (call_byte) {
                uint32_t call_num = *call_byte;
                // Look up the MLI call name
                auto call_symbol = symbol_table->GetSymbol(call_num);
                if (call_symbol && call_symbol->type == core::SymbolType::MLI_CALL) {
                  comment = "MLI " + call_symbol->name + " call parameters";
                } else {
                  comment = symbol->name + " inline parameters";
                }
              }
            }
          }
        }

        // Mark bytes and add comment if generated
        for (size_t i = 0; i < inline_bytes; ++i) {
          if (IsValidAddress(data_addr + i)) {
            address_map->SetType(data_addr + i, core::AddressType::INLINE_DATA);
            marked_count++;
            LOG_DEBUG("Pre-marked INLINE_DATA at $" + std::to_string(data_addr + i) +
                      " after JSR to $" + std::to_string(inst.target_address));
          }
        }

        // Add comment(s) to the first inline data byte
        if (!comment.empty() && IsValidAddress(data_addr)) {
          // Build full comment with parameter details
          std::string full_comment = comment;
          if (!parameter_comments.empty()) {
            full_comment += "\n";
            for (const auto& param_comment : parameter_comments) {
              full_comment += param_comment + "\n";
            }
            // Remove trailing newline
            if (!full_comment.empty() && full_comment.back() == '\n') {
              full_comment.pop_back();
            }
          }

          address_map->SetComment(data_addr, full_comment);
          LOG_DEBUG("Added comment to INLINE_DATA at $" + std::to_string(data_addr) +
                    ": " + comment);
          if (!parameter_comments.empty()) {
            LOG_DEBUG("  With " + std::to_string(parameter_comments.size()) +
                      " parameter details");
          }
        }
      }
    }
  }

  if (marked_count > 0) {
    LOG_INFO("Pre-scan marked " + std::to_string(marked_count) + " inline data bytes");
  }

  return marked_count;
}

}  // namespace analysis
}  // namespace sourcerer
