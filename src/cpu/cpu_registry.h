// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_CPU_CPU_REGISTRY_H_
#define SOURCERER_CPU_CPU_REGISTRY_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "cpu/cpu_plugin.h"

namespace sourcerer {
namespace cpu {

// Convert CpuVariant enum to registry name string
std::string CpuVariantToString(CpuVariant variant);

// Registry for CPU plugins
class CpuRegistry {
 public:
  static CpuRegistry& Instance();

  // Register a CPU plugin
  void Register(const std::string& name, CpuPluginFactory factory);

  // Create a CPU plugin by name
  std::unique_ptr<CpuPlugin> Create(const std::string& name) const;

  // Create a CPU plugin by variant (type-safe)
  std::unique_ptr<CpuPlugin> Create(CpuVariant variant) const;

  // Check if a CPU plugin is registered
  bool IsRegistered(const std::string& name) const;

  // Get list of registered CPU names
  std::vector<std::string> GetRegisteredNames() const;

  // Prevent copying
  CpuRegistry(const CpuRegistry&) = delete;
  CpuRegistry& operator=(const CpuRegistry&) = delete;

 private:
  CpuRegistry();
  void RegisterBuiltinCpus();

  std::map<std::string, CpuPluginFactory> factories_;
};

}  // namespace cpu
}  // namespace sourcerer

#endif  // SOURCERER_CPU_CPU_REGISTRY_H_
