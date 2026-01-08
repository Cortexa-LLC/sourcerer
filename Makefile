# Sourcerer - Convenient build targets

.PHONY: all build test coverage clean clean-all clean-coverage clean-gcov help

# Default target
all: build

# Build regular version
build:
	@cmake -B build -DCMAKE_BUILD_TYPE=Debug
	@cmake --build build

# Build and run tests
test: build
	@cd build && ctest --output-on-failure

# Build with coverage and run tests
coverage:
	@cmake -B build_coverage -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS="--coverage" -DBUILD_TESTING=ON
	@cmake --build build_coverage
	@cd build_coverage && ctest

# Clean build artifacts from build_coverage
clean-coverage:
	@echo "Cleaning coverage build artifacts..."
	@find build_coverage -name "*.gcda" -delete 2>/dev/null || true
	@find build_coverage -name "*.gcno" -delete 2>/dev/null || true
	@echo "Coverage artifacts cleaned"

# Clean .gcov files from project root
clean-gcov:
	@echo "Cleaning .gcov files from root..."
	@rm -f *.gcov
	@echo ".gcov files cleaned"

# Clean all build directories
clean-all:
	@echo "Removing all build directories..."
	@rm -rf build build_coverage build_cov build_gcov
	@echo "All build directories removed"

# Standard clean (keep build dirs, clean artifacts)
clean: clean-gcov clean-coverage
	@echo "Cleaning build artifacts..."
	@cd build && make clean 2>/dev/null || true
	@cd build_coverage && make clean 2>/dev/null || true
	@echo "Build artifacts cleaned"

# Help target
help:
	@echo "Sourcerer Build Targets:"
	@echo ""
	@echo "  make build          - Build project (debug)"
	@echo "  make test           - Build and run tests"
	@echo "  make coverage       - Build with coverage and run tests"
	@echo ""
	@echo "  make clean          - Clean build artifacts (keep build dirs)"
	@echo "  make clean-coverage - Remove coverage artifacts (.gcda, .gcno)"
	@echo "  make clean-gcov     - Remove .gcov files from root"
	@echo "  make clean-all      - Remove all build directories"
	@echo ""
	@echo "  make help           - Show this help"
