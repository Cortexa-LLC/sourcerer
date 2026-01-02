// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "core/instruction.h"

namespace sourcerer {
namespace core {

Instruction::Instruction()
    : address(0),
      mode(AddressingMode::UNKNOWN),
      target_address(0),
      is_branch(false),
      is_jump(false),
      is_call(false),
      is_return(false),
      is_illegal(false) {}

std::string Instruction::ToString() const {
  if (operand.empty()) {
    return mnemonic;
  }
  return mnemonic + " " + operand;
}

}  // namespace core
}  // namespace sourcerer
