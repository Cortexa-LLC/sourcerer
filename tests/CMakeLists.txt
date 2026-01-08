# Copyright (c) 2025 Cortexa LLC
# SPDX-License-Identifier: MIT

# Unit tests for sourcerer

# Test executable for core modules
add_executable(test_core
    test_binary.cpp
    test_instruction.cpp
    test_address_map.cpp
    test_symbol_table.cpp
)
target_link_libraries(test_core PRIVATE
    sourcerer_core
    utils
    GTest::gtest
    GTest::gtest_main
)
gtest_discover_tests(test_core)

# Test executable for CPU plugins
add_executable(test_6502
    test_cpu_6502.cpp
    test_opcodes_6502.cpp
)
target_link_libraries(test_6502 PRIVATE
    cpu_plugins
    utils
    GTest::gtest
    GTest::gtest_main
)
gtest_discover_tests(test_6502)

# Test executable for 6809 CPU plugin
add_executable(test_6809
    test_cpu_6809.cpp
)
target_link_libraries(test_6809 PRIVATE
    cpu_plugins
    utils
    GTest::gtest
    GTest::gtest_main
)
gtest_discover_tests(test_6809)

# Test executable for analysis modules
add_executable(test_analysis
    test_hints_parser.cpp
    test_label_generator.cpp
    test_xref_builder.cpp
    test_execution_simulator_enhanced.cpp
    test_code_analyzer_integration.cpp
    test_pattern_detector.cpp
)
target_link_libraries(test_analysis PRIVATE
    analysis
    cpu_plugins
    utils
    GTest::gtest
    GTest::gtest_main
)
gtest_discover_tests(test_analysis)

# Test executable for formatters
add_executable(test_formatters
    test_merlin_formatter.cpp
    test_scmasm_formatter.cpp
    test_edtasm_formatter.cpp
)
target_link_libraries(test_formatters PRIVATE
    formatters
    analysis
    utils
    GTest::gtest
    GTest::gtest_main
)
gtest_discover_tests(test_formatters)

# Integration tests
add_executable(test_integration
    test_integration.cpp
)
target_link_libraries(test_integration PRIVATE
    sourcerer_core
    cpu_plugins
    disk_extractors
    formatters
    analysis
    utils
    GTest::gtest
    GTest::gtest_main
)
gtest_discover_tests(test_integration)
