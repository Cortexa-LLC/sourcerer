// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_CORE_EQUATE_PROVIDER_H_
#define SOURCERER_CORE_EQUATE_PROVIDER_H_

#include <map>
#include <string>

namespace sourcerer {
namespace core {

/**
 * Abstract interface for providing equate definitions (named constants).
 *
 * Allows output formatters to remain independent of analysis layer by depending
 * only on this interface. Implementations can generate equates from instruction
 * analysis, platform definitions, or user-provided files.
 *
 * Equates map immediate values (uint8_t) to named constants for cleaner assembly output.
 * Example: LDA #$FF becomes LDA #MAXVAL where MAXVAL EQU $FF
 */
class IEquateProvider {
 public:
  virtual ~IEquateProvider() = default;

  /**
   * Check if a value has an associated equate.
   * @param value Immediate value to check
   * @return true if equate exists for this value
   */
  virtual bool HasEquate(uint8_t value) const = 0;

  /**
   * Get equate name for a value.
   * @param value Immediate value
   * @return Equate name, or empty string if not found
   */
  virtual std::string GetEquateName(uint8_t value) const = 0;

  /**
   * Get all equates (value -> name mapping).
   * @return Map of immediate values to equate names
   */
  virtual const std::map<uint8_t, std::string>& GetEquates() const = 0;

  /**
   * Get equate comment/description for a value.
   * @param value Immediate value
   * @return Comment string, or empty if not found
   */
  virtual std::string GetEquateComment(uint8_t value) const = 0;
};

}  // namespace core
}  // namespace sourcerer

#endif  // SOURCERER_CORE_EQUATE_PROVIDER_H_
