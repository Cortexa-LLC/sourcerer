// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>

#include "analysis/code_analyzer.h"
#include "analysis/equate_generator.h"
#include "analysis/hints_parser.h"
#include "analysis/label_generator.h"
#include "analysis/xref_builder.h"
#include "core/address_map.h"
#include "core/binary.h"
#include "core/disasm_context.h"
#include "core/instruction.h"
#include "core/symbol_table.h"
#include "cpu/cpu_registry.h"
#include "disk/disk_registry.h"
#include "output/formatter_registry.h"
#include "utils/cli_parser.h"
#include "utils/logger.h"

using namespace sourcerer;

// Disassemble with code flow analysis
std::vector<core::Instruction> DisassembleWithAnalysis(
    cpu::CpuPlugin* cpu,
    const core::Binary& binary,
    core::AddressMap* address_map) {
  
  std::vector<core::Instruction> instructions;
  
  // Run code flow analysis
  LOG_INFO("Running code flow analysis...");
  analysis::CodeAnalyzer analyzer(cpu, &binary);
  
  // Add entry point (load address by default)
  analyzer.AddEntryPoint(binary.load_address());
  
  // Analyze
  analyzer.Analyze(address_map);
  
  // Now disassemble only the code regions
  uint32_t address = binary.load_address();
  uint32_t end_address = address + binary.size();
  
  LOG_INFO("Disassembling code regions...");
  
  while (address < end_address) {
    // Skip data regions
    if (address_map->IsData(address)) {
      address++;
      continue;
    }
    
    // Skip if not code
    if (!address_map->IsCode(address)) {
      address++;
      continue;
    }
    
    const uint8_t* data = binary.GetPointer(address);
    size_t remaining = end_address - address;
    
    if (!data || remaining == 0) {
      break;
    }
    
    try {
      core::Instruction inst = cpu->Disassemble(data, remaining, address);
      instructions.push_back(inst);
      
      // Move to next instruction
      address += inst.bytes.size();
      
    } catch (const std::exception& e) {
      LOG_ERROR("Disassembly failed at $" + std::to_string(address) + 
                ": " + e.what());
      address++;
    }
  }
  
  LOG_INFO("Disassembled " + std::to_string(instructions.size()) + 
           " instructions from code regions");
  return instructions;
}

// Linear disassembly (no code flow analysis)
std::vector<core::Instruction> DisassembleLinear(
    cpu::CpuPlugin* cpu,
    const core::Binary& binary) {
  
  std::vector<core::Instruction> instructions;
  
  uint32_t address = binary.load_address();
  uint32_t end_address = address + binary.size();
  
  LOG_INFO("Linear disassembly from $" + 
           std::to_string(address) + " to $" + 
           std::to_string(end_address));
  
  while (address < end_address) {
    const uint8_t* data = binary.GetPointer(address);
    size_t remaining = end_address - address;
    
    if (!data || remaining == 0) {
      break;
    }
    
    try {
      core::Instruction inst = cpu->Disassemble(data, remaining, address);
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

// List files in disk image
int ListDiskFiles(const std::string& disk_path) {
  LOG_INFO("Listing files in: " + disk_path);
  
  auto extractor = disk::DiskRegistry::Instance().FindExtractor(disk_path);
  if (!extractor) {
    LOG_ERROR("No disk extractor found for: " + disk_path);
    return 1;
  }
  
  LOG_INFO("Using extractor: " + extractor->Name());
  
  if (!extractor->IsValidDisk(disk_path)) {
    LOG_ERROR("Invalid or unreadable disk image: " + disk_path);
    return 1;
  }
  
  auto files = extractor->ListFiles(disk_path);
  if (files.empty()) {
    LOG_INFO("No files found in disk image");
    return 0;
  }
  
  std::cout << std::endl;
  std::cout << "Files in " << disk_path << ":" << std::endl;
  std::cout << "----------------------------------------" << std::endl;
  std::cout << std::left << std::setw(30) << "Name" 
            << std::setw(8) << "Type"
            << std::setw(10) << "Size"
            << "Load Addr" << std::endl;
  std::cout << "----------------------------------------" << std::endl;
  
  for (const auto& file : files) {
    std::cout << std::left << std::setw(30) << file.name
              << std::setw(8) << file.file_type
              << std::setw(10) << file.size;
    
    if (file.has_load_address) {
      std::cout << "$" << std::hex << std::uppercase 
                << std::setw(4) << std::setfill('0')
                << file.load_address;
    } else {
      std::cout << "N/A";
    }
    std::cout << std::endl;
  }
  std::cout << std::endl;
  
  return 0;
}

// Load binary from disk or file
core::Binary LoadBinary(const utils::CliOptions& options) {
  if (options.is_disk) {
    // Extract from disk image
    LOG_INFO("Extracting from disk: " + options.input_file);
    
    auto extractor = disk::DiskRegistry::Instance().FindExtractor(options.input_file);
    if (!extractor) {
      throw std::runtime_error("No disk extractor found for: " + options.input_file);
    }
    
    LOG_INFO("Using extractor: " + extractor->Name());
    
    if (!extractor->IsValidDisk(options.input_file)) {
      throw std::runtime_error("Invalid or unreadable disk image: " + options.input_file);
    }
    
    if (options.disk_file_name.empty()) {
      throw std::runtime_error("--file option required when using --disk");
    }
    
    core::Binary binary = extractor->ExtractFile(options.input_file, 
                                                 options.disk_file_name);
    
    // Override load address if specified
    if (options.load_address != 0) {
      binary.set_load_address(options.load_address);
      LOG_INFO("Load address overridden to $" + std::to_string(options.load_address));
    }
    
    return binary;
    
  } else {
    // Load raw binary file
    LOG_INFO("Loading raw binary: " + options.input_file);
    
    uint32_t load_addr = options.load_address;
    if (load_addr == 0) {
      load_addr = 0x8000;  // Default for Apple II
      LOG_INFO("Using default load address: $8000");
    }
    
    core::Binary binary = core::Binary::LoadFromFile(options.input_file, load_addr);
    binary.set_file_type("RAW");
    
    return binary;
  }
}

int main(int argc, char** argv) {
  // Parse command-line arguments
  utils::CliParser parser;
  utils::CliOptions options;
  std::string error;

  if (!parser.Parse(argc, argv, &options, &error)) {
    LOG_ERROR(error);
    std::cout << parser.GetHelp() << std::endl;
    return 1;
  }

  // Set log level
  if (options.verbose) {
    utils::Logger::Instance().SetLevel(utils::LogLevel::DEBUG);
  }

  LOG_INFO("Sourcerer - Modern Multi-CPU Disassembler");
  LOG_INFO("Version 1.0.0");
  LOG_INFO("");

  try {
    // Handle --list-files
    if (options.list_files) {
      return ListDiskFiles(options.input_file);
    }

    // Validate required options
    if (options.input_file.empty()) {
      LOG_ERROR("Input file required (-i or --input)");
      std::cout << parser.GetHelp() << std::endl;
      return 1;
    }
    
    if (options.output_file.empty()) {
      LOG_ERROR("Output file required (-o or --output)");
      std::cout << parser.GetHelp() << std::endl;
      return 1;
    }

    // Load binary
    LOG_INFO("Loading binary...");
    core::Binary binary = LoadBinary(options);
    LOG_INFO("Loaded " + std::to_string(binary.size()) + " bytes at $" + 
             std::to_string(binary.load_address()));

    // Create CPU plugin
    LOG_INFO("Initializing CPU plugin: " + options.cpu_type);
    auto cpu = cpu::CpuRegistry::Instance().Create(options.cpu_type);
    if (!cpu) {
      LOG_ERROR("Unknown CPU type: " + options.cpu_type);
      return 1;
    }
    LOG_INFO("Using CPU: " + cpu->Name());

    // Auto-load platform symbols if platform specified
    if (!options.platform.empty()) {
      LOG_INFO("Platform: " + options.platform);
      LOG_INFO("Searching for platform-specific symbol files...");

      // Look for symbols/{platform}_*.json files
      std::string symbols_dir = "symbols";
      std::string platform_prefix = options.platform + "_";

      try {
        if (std::filesystem::exists(symbols_dir) &&
            std::filesystem::is_directory(symbols_dir)) {

          for (const auto& entry : std::filesystem::directory_iterator(symbols_dir)) {
            if (entry.is_regular_file()) {
              std::string filename = entry.path().filename().string();
              std::string extension = entry.path().extension().string();

              // Check if file matches {platform}_*.json pattern
              if (extension == ".json" &&
                  filename.size() > platform_prefix.size() &&
                  filename.substr(0, platform_prefix.size()) == platform_prefix) {

                std::string full_path = entry.path().string();
                options.symbols_files.push_back(full_path);
                LOG_INFO("  Found: " + filename);
              }
            }
          }

          if (options.symbols_files.empty()) {
            LOG_INFO("  No platform-specific symbol files found for: " +
                     options.platform);
          }
        } else {
          LOG_INFO("  Symbols directory not found: " + symbols_dir);
        }
      } catch (const std::filesystem::filesystem_error& e) {
        LOG_ERROR("Error scanning symbols directory: " + std::string(e.what()));
      }
    }

    // Load symbol tables if specified
    core::SymbolTable symbol_table;
    core::SymbolTable* symbol_table_ptr = nullptr;

    if (!options.symbols_files.empty()) {
      LOG_INFO("Loading symbol tables...");
      for (const auto& symbols_file : options.symbols_files) {
        LOG_INFO("  Loading: " + symbols_file);
        if (!symbol_table.LoadFromFile(symbols_file)) {
          LOG_ERROR("Failed to load symbol table: " + symbols_file);
        } else {
          LOG_INFO("  Loaded successfully");
        }
      }
      symbol_table_ptr = &symbol_table;
    }

    // Load and apply hints if specified
    analysis::Hints hints;
    if (!options.hints_file.empty()) {
      LOG_INFO("Loading hints from: " + options.hints_file);
      analysis::HintsParser hints_parser;
      std::string hints_error;
      if (!hints_parser.ParseFile(options.hints_file, &hints, &hints_error)) {
        LOG_ERROR("Failed to parse hints file: " + hints_error);
        return 1;
      }
      LOG_INFO("Hints loaded successfully");
    }

    // Create address map for analysis
    core::AddressMap address_map;
    core::AddressMap* address_map_ptr = nullptr;

    // Apply hints to address map before analysis
    if (!options.hints_file.empty()) {
      LOG_INFO("Applying hints to address map...");
      analysis::HintsParser::ApplyHints(hints, &address_map);
      LOG_INFO("Hints applied");
    }

    // Disassemble
    std::vector<core::Instruction> instructions;

    if (options.enable_analysis) {
      LOG_INFO("Code flow analysis enabled");
      instructions = DisassembleWithAnalysis(cpu.get(), binary, &address_map);
      address_map_ptr = &address_map;

      // Always build cross-references (needed for label generation)
      LOG_INFO("Building cross-references...");
      analysis::XrefBuilder xref_builder(&address_map);
      xref_builder.BuildXrefs(instructions);

      // Add xref comments if enabled
      if (options.generate_xrefs) {
        xref_builder.AddXrefComments();
        LOG_INFO("Cross-reference comments added");
      } else {
        LOG_INFO("Cross-references built (for label generation)");
      }

      // Generate labels if enabled
      if (options.generate_labels) {
        LOG_INFO("Generating labels...");
        analysis::LabelGenerator label_gen(&address_map, &binary, symbol_table_ptr);
        label_gen.GenerateLabels(&instructions);
        LOG_INFO("Labels generated");
      }
    } else {
      LOG_INFO("Linear disassembly mode (analysis disabled)");
      instructions = DisassembleLinear(cpu.get(), binary);
    }

    // Generate equates for commonly used immediate values
    analysis::EquateGenerator equate_gen(3);  // Minimum 3 uses to generate equate
    equate_gen.AnalyzeInstructions(instructions);

    // Create output formatter
    LOG_INFO("Initializing output formatter: " + options.output_format);
    auto formatter = output::FormatterRegistry::Instance().Create(options.output_format);
    if (!formatter) {
      LOG_ERROR("Unknown output format: " + options.output_format);
      return 1;
    }
    LOG_INFO("Using formatter: " + formatter->Name());

    // Format output
    LOG_INFO("Formatting output...");
    LOG_INFO("Passing " + std::to_string(instructions.size()) + " instructions to formatter");
    std::string output = formatter->Format(binary, instructions, address_map_ptr,
                                          symbol_table_ptr, &equate_gen);

    // Write to file
    LOG_INFO("Writing output...");
    std::ofstream out_file(options.output_file);
    if (!out_file) {
      LOG_ERROR("Failed to open output file: " + options.output_file);
      return 1;
    }
    out_file << output;
    out_file.close();

    LOG_INFO("Output written to: " + options.output_file);
    LOG_INFO("Disassembly complete!");
    return 0;

  } catch (const std::exception& e) {
    LOG_ERROR("Fatal error: " + std::string(e.what()));
    return 1;
  }
}
