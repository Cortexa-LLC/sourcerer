// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "cpu/cpu_registry.h"

#include "cpu/m6502/cpu_6502.h"
#include "cpu/m6809/cpu_6809.h"
#include "utils/logger.h"

namespace sourcerer {
namespace cpu {

std::string CpuVariantToString(CpuVariant variant) {
  switch (variant) {
    case CpuVariant::MOS_6502:
      return "6502";
    case CpuVariant::WDC_65C02:
      return "65c02";
    case CpuVariant::WDC_65816:
      return "65816";
    case CpuVariant::MOTOROLA_6809:
      return "6809";
    case CpuVariant::ZILOG_Z80:
      return "z80";
    default:
      return "unknown";
  }
}

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

  // Register 6809 plugin
  Register("6809", &m6809::Create6809Plugin);
  LOG_INFO("Registered 6809 CPU plugin");
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

std::unique_ptr<CpuPlugin> CpuRegistry::Create(CpuVariant variant) const {
  return Create(CpuVariantToString(variant));
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
