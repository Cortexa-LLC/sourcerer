cmake_minimum_required(VERSION 3.15)
project(sourcerer VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Options
option(BUILD_TESTING "Build tests" OFF)  # Disabled by default, tests are pending
option(ENABLE_WARNINGS "Enable compiler warnings" ON)

# Compiler flags (Google Style Guide recommendations)
if(ENABLE_WARNINGS)
    if(MSVC)
        add_compile_options(/W4)
    else()
        add_compile_options(-Wall -Wextra -Wpedantic)
    endif()
endif()

# Dependencies via FetchContent
include(FetchContent)

# CLI11 for command-line parsing (using v2.4.2 for CMake 4.x compatibility)
FetchContent_Declare(
    cli11
    GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
    GIT_TAG v2.4.2
)

# nlohmann_json for JSON parsing (using v3.11.3 for latest features)
FetchContent_Declare(
    json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
)

# Google Test for unit testing
if(BUILD_TESTING)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.14.0
    )
    # Prevent GoogleTest from overriding compiler/linker options
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
endif()

FetchContent_MakeAvailable(cli11 json)
if(BUILD_TESTING)
    FetchContent_MakeAvailable(googletest)
    enable_testing()
    include(GoogleTest)
endif()

# Core library
add_library(sourcerer_core
    src/core/binary.cpp
    src/core/instruction.cpp
    src/core/address_map.cpp
    src/core/disasm_context.cpp
    src/core/symbol_table.cpp
)
target_include_directories(sourcerer_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(sourcerer_core PUBLIC
    nlohmann_json::nlohmann_json
)

# CPU plugins
add_library(cpu_plugins
    src/cpu/cpu_registry.cpp
    src/cpu/m6502/cpu_6502.cpp
    src/cpu/m6502/opcodes_6502.cpp
    src/cpu/m6809/cpu_6809.cpp
    src/cpu/m6809/opcodes_6809.cpp
    src/cpu/m6809/indexed_mode.cpp
)
target_link_libraries(cpu_plugins PUBLIC sourcerer_core)

# Disk extractors
add_library(disk_extractors
    src/disk/disk_registry.cpp
    src/disk/acx_extractor.cpp
    src/disk/coco_extractor.cpp
    src/disk/raw_file.cpp
)
target_link_libraries(disk_extractors PUBLIC sourcerer_core)

# Output formatters
add_library(formatters
    src/output/formatter_registry.cpp
    src/output/data_collector.cpp
    src/output/address_analyzer.cpp
    src/output/label_resolver.cpp
    src/output/merlin_formatter.cpp
    src/output/scmasm_formatter.cpp
    src/output/edtasm_formatter.cpp
)
target_link_libraries(formatters PUBLIC sourcerer_core)

# Analysis modules
add_library(analysis
    src/analysis/code_analyzer.cpp
    src/analysis/execution_simulator.cpp
    src/analysis/label_generator.cpp
    src/analysis/xref_builder.cpp
    src/analysis/hints_parser.cpp
    src/analysis/equate_generator.cpp
    src/analysis/pattern_detector.cpp
)
target_link_libraries(analysis PUBLIC
    sourcerer_core
    nlohmann_json::nlohmann_json
)

# Utilities
add_library(utils
    src/utils/cli_parser.cpp
    src/utils/logger.cpp
)
target_include_directories(utils PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(utils PUBLIC CLI11::CLI11)

# Main executable
add_executable(sourcerer
    src/main.cpp
)
target_link_libraries(sourcerer PRIVATE
    cpu_plugins
    disk_extractors
    formatters
    analysis
    utils
)

# Tests
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

# Installation
install(TARGETS sourcerer DESTINATION bin)
install(DIRECTORY examples/ DESTINATION share/sourcerer/examples
        PATTERN "*.bin" EXCLUDE)  # Exclude binaries from install
install(DIRECTORY symbols/ DESTINATION share/sourcerer/symbols)
install(FILES README.md LICENSE DESTINATION share/doc/sourcerer)

# Uninstall target
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)

add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
