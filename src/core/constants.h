// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#ifndef SOURCERER_CORE_CONSTANTS_H_
#define SOURCERER_CORE_CONSTANTS_H_

#include <cstddef>
#include <cstdint>

namespace sourcerer {
namespace constants {

// Analysis constants
constexpr size_t kMinDataRegionSize = 16;
constexpr int kMinHeuristicMatches = 2;
constexpr float kPrintableThresholdHigh = 0.90f;
constexpr float kPrintableThresholdLow = 0.50f;
constexpr int kMaxRecursionDepth = 1000;
constexpr int kMaxAnalysisPasses = 10;
constexpr size_t kDefaultMaxInstructions = 100000;
constexpr size_t kMaxDataScan = 64;

// Jump table detection constants
constexpr size_t kMinJumpTableEntries = 3;
constexpr size_t kMaxJumpTableEntries = 256;
constexpr float kMinJumpTableConfidence = 0.6f;

// Data heuristics thresholds
constexpr size_t kMinStringLength = 4;
constexpr size_t kMinRepeatedBytes = 8;
constexpr float kMinEntropyForGraphics = 3.0f;
constexpr float kMaxEntropyForGraphics = 7.0f;

// ASCII character constants
constexpr uint8_t kAsciiMask = 0x7F;
constexpr uint8_t kPrintableMin = 0x20;
constexpr uint8_t kPrintableMax = 0x7F;

// String detection constants
constexpr size_t kMinPrintableSequenceLength = 24;
constexpr int kStringLookbackDistance = 10;
constexpr int kMinPrintableBeforeNull = 3;
constexpr int kMinNullTerminatedStrings = 1;

// Repeated byte detection
constexpr int kMinRepeatedByteCount = 4;

// Address pair detection
constexpr size_t kMinRegionSizeForAddressPairs = 8;
constexpr uint16_t kAddressLowerThreshold = 0x0100;
constexpr uint16_t kAddressUpperThreshold = 0x0800;
constexpr int kAddressPairProportionDenom = 4;

// Repeated instruction pattern detection
constexpr int kMinRepeatedInstructionPatterns = 8;

// Illegal opcode detection
constexpr size_t kMinRegionSizeForIllegalCheck = 16;
constexpr int kSuspiciousOpcodeProportionDenom = 4;

// Default load addresses by platform
constexpr uint32_t kDefaultAppleIILoadAddress = 0x8000;
constexpr uint32_t kDefaultCoCoLoadAddress = 0x0600;
constexpr uint32_t kDefaultC64LoadAddress = 0x0801;

// CoCo cartridge constants
constexpr uint32_t kCoCoCartridgeStart = 0xC000;
constexpr uint32_t kCoCoCartridgeEnd = 0xFEFF;

// Formatting constants
constexpr int kDefaultOpcodeColumn = 10;
constexpr int kDefaultCommentColumn = 40;
constexpr int kMaxBytesPerLine = 8;
constexpr int kMaxDataBytesPerLine = 16;

// Symbol table constants
constexpr int kMinEquateUses = 3;

// Inline data constants
constexpr uint32_t kProDosMLIAddress = 0xBF00;
constexpr size_t kProDosMLIParameterBytes = 3;

// Analysis confidence thresholds
constexpr float kMinInstructionConfidence = 0.5f;
constexpr float kHighConfidenceThreshold = 0.8f;

// Xref and cross-reference limits
constexpr size_t kMaxXrefsPerAddress = 100;

}  // namespace constants
}  // namespace sourcerer

#endif  // SOURCERER_CORE_CONSTANTS_H_
