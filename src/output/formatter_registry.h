// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_OUTPUT_FORMATTER_REGISTRY_H_
#define SOURCERER_OUTPUT_FORMATTER_REGISTRY_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "output/formatter.h"

namespace sourcerer {
namespace output {

// Registry for output formatters
class FormatterRegistry {
 public:
  static FormatterRegistry& Instance();

  // Register a formatter
  void Register(const std::string& name, FormatterFactory factory);

  // Create a formatter by name
  std::unique_ptr<Formatter> Create(const std::string& name) const;

  // Check if a formatter is registered
  bool IsRegistered(const std::string& name) const;

  // Get list of registered formatter names
  std::vector<std::string> GetRegisteredNames() const;

  // Prevent copying
  FormatterRegistry(const FormatterRegistry&) = delete;
  FormatterRegistry& operator=(const FormatterRegistry&) = delete;

 private:
  FormatterRegistry();
  void RegisterBuiltinFormatters();

  std::map<std::string, FormatterFactory> factories_;
};

}  // namespace output
}  // namespace sourcerer

#endif  // SOURCERER_OUTPUT_FORMATTER_REGISTRY_H_
