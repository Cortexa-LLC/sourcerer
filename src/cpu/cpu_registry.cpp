// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "cpu/cpu_registry.h"

#include "cpu/m6502/cpu_6502.h"
#include "utils/logger.h"

namespace sourcerer {
namespace cpu {

CpuRegistry& CpuRegistry::Instance() {
  static CpuRegistry instance;
  return instance;
}

CpuRegistry::CpuRegistry() {
  RegisterBuiltinCpus();
}

void CpuRegistry::RegisterBuiltinCpus() {
  // Register 6502 family plugins
  Register("6502", &m6502::Create6502Plugin);
  Register("65c02", &m6502::Create65C02Plugin);
  LOG_INFO("Registered 6502 family CPU plugins");
}

void CpuRegistry::Register(const std::string& name, CpuPluginFactory factory) {
  factories_[name] = factory;
  LOG_DEBUG("Registered CPU plugin: " + name);
}

std::unique_ptr<CpuPlugin> CpuRegistry::Create(const std::string& name) const {
  auto it = factories_.find(name);
  if (it != factories_.end()) {
    return it->second();
  }
  LOG_ERROR("CPU plugin not found: " + name);
  return nullptr;
}

bool CpuRegistry::IsRegistered(const std::string& name) const {
  return factories_.find(name) != factories_.end();
}

std::vector<std::string> CpuRegistry::GetRegisteredNames() const {
  std::vector<std::string> names;
  for (const auto& pair : factories_) {
    names.push_back(pair.first);
  }
  return names;
}

}  // namespace cpu
}  // namespace sourcerer
