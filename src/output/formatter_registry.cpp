// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "output/formatter_registry.h"

#include "output/merlin_formatter.h"
#include "output/scmasm_formatter.h"
#include "utils/logger.h"

namespace sourcerer {
namespace output {

FormatterRegistry& FormatterRegistry::Instance() {
  static FormatterRegistry instance;
  return instance;
}

FormatterRegistry::FormatterRegistry() {
  RegisterBuiltinFormatters();
}

void FormatterRegistry::RegisterBuiltinFormatters() {
  // Register Merlin formatter
  Register("merlin", &CreateMerlinFormatter);

  // Register SCMASM formatter
  Register("scmasm", &CreateScmasmFormatter);

  LOG_INFO("Registered output formatters");
}

void FormatterRegistry::Register(const std::string& name,
                                FormatterFactory factory) {
  factories_[name] = factory;
  LOG_DEBUG("Registered output formatter: " + name);
}

std::unique_ptr<Formatter> FormatterRegistry::Create(
    const std::string& name) const {
  auto it = factories_.find(name);
  if (it != factories_.end()) {
    return it->second();
  }
  LOG_ERROR("Output formatter not found: " + name);
  return nullptr;
}

bool FormatterRegistry::IsRegistered(const std::string& name) const {
  return factories_.find(name) != factories_.end();
}

std::vector<std::string> FormatterRegistry::GetRegisteredNames() const {
  std::vector<std::string> names;
  for (const auto& pair : factories_) {
    names.push_back(pair.first);
  }
  return names;
}

}  // namespace output
}  // namespace sourcerer
