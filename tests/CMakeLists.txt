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

# Round-trip validation tests (Python-based integration tests)
# These tests validate: Binary → Disassemble → Reassemble → Binary comparison
find_package(Python3 COMPONENTS Interpreter)

if(Python3_FOUND)
    # Check if assemblers are available
    find_program(VASM6809_EDTASM vasm6809_edtasm)
    find_program(VASM6502_MERLIN vasm6502_merlin)

    if(VASM6809_EDTASM AND VASM6502_MERLIN)
        # Add round-trip validation test
        add_test(
            NAME roundtrip_validation
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test_roundtrip.py
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        )

        # Ensure sourcerer is built before running round-trip tests
        set_tests_properties(roundtrip_validation PROPERTIES
            DEPENDS sourcerer
            LABELS "integration"
        )

        message(STATUS "Round-trip validation tests enabled")
        message(STATUS "  Python3: ${Python3_EXECUTABLE}")
        message(STATUS "  vasm6809_edtasm: ${VASM6809_EDTASM}")
        message(STATUS "  vasm6502_merlin: ${VASM6502_MERLIN}")
    else()
        message(STATUS "Round-trip validation tests disabled (assemblers not found)")
        if(NOT VASM6809_EDTASM)
            message(STATUS "  Missing: vasm6809_edtasm")
        endif()
        if(NOT VASM6502_MERLIN)
            message(STATUS "  Missing: vasm6502_merlin")
        endif()
    endif()
else()
    message(STATUS "Round-trip validation tests disabled (Python3 not found)")
endif()
