// Copyright (c) 2025 Cortexa LLC
// SPDX-License-Identifier: MIT

#include "analysis/llm/claude_analyzer.h"

#include <cstdlib>
#include <iomanip>
#include <sstream>

// CPPHTTPLIB_OPENSSL_SUPPORT is defined via compiler flag (-DCPPHTTPLIB_OPENSSL_SUPPORT)
// so we do not redefine it here to avoid -Wmacro-redefined warnings.
#include <httplib.h>
#include <nlohmann/json.hpp>

#include "analysis/llm/code_pattern_detector.h"
#include "analysis/llm/data_code_scanner.h"
#include "analysis/llm/string_scanner.h"
#include "cpu/cpu_plugin.h"
#include "utils/logger.h"

namespace sourcerer {
namespace analysis {
namespace llm {

using json = nlohmann::json;

namespace {
// Returns all segments of the binary (flat or multi-segment).
std::vector<core::BinarySegment> AllSegments(const core::Binary& binary) {
  if (!binary.segments().empty()) return binary.segments();
  if (!binary.data().empty()) {
    core::BinarySegment seg;
    seg.data = binary.data();
    seg.load_address = binary.load_address();
    return {std::move(seg)};
  }
  return {};
}
}  // namespace

ClaudeAnalyzer::ClaudeAnalyzer() {
  const char* key = std::getenv("ANTHROPIC_API_KEY");
  if (key) api_key_ = key;
  // Missing key is reported by the caller via HasApiKey(); no log here.
}

void ClaudeAnalyzer::Configure(const std::string& model, const std::string& url) {
  if (!model.empty()) model_ = model;

  if (!url.empty()) {
    // Split a full URL like "https://api.anthropic.com/v1/messages" into
    // base ("https://api.anthropic.com") and path ("/v1/messages").
    // If no path component is present, keep the default api_path_.
    size_t scheme_end = url.find("://");
    size_t host_start = (scheme_end != std::string::npos) ? scheme_end + 3 : 0;
    size_t path_start = url.find('/', host_start);
    if (path_start != std::string::npos) {
      api_base_url_ = url.substr(0, path_start);
      api_path_     = url.substr(path_start);
    } else {
      api_base_url_ = url;
      // api_path_ retains its default "/v1/messages"
    }
  }
}

// static
std::string ClaudeAnalyzer::BuildSystemPrompt() {
  return
      "You are an expert vintage computer system analyst specializing in 6502 "
      "and related CPU assembly disassembly. Your task is to analyze disassembled "
      "code and produce meaningful, human-readable labels and inline comments that "
      "explain the purpose and intent of each address.\n\n"
      "Rules:\n"
      "- Labels must be valid assembler identifiers (letters, digits, underscore; "
      "must start with a letter or underscore; ≤ 15 chars recommended).\n"
      "- Comments must be concise (≤ 60 chars), describing what the code DOES "
      "rather than what the instruction IS.\n"
      "- Only annotate addresses that appear in the provided listing. Do NOT invent "
      "addresses.\n"
      "- If the purpose of an address is unclear, omit it from the response rather "
      "than guessing.\n"
      "- Use the annotate_code tool to return your structured results.";
}

// static
std::string ClaudeAnalyzer::BuildUserMessage(const std::string& chunk_context) {
  return "Analyze the following 6502 disassembly listing and provide improved "
         "labels and inline comments using the annotate_code tool.\n\n"
         "```\n" + chunk_context + "\n```";
}

std::vector<LlmAnnotation> ClaudeAnalyzer::Analyze(
    const std::string& chunk_context,
    const std::vector<core::Instruction>& /*instructions*/) {

  if (api_key_.empty()) {
    LOG_WARNING("Skipping Claude analysis: no API key.");
    return {};
  }

  // Build request body
  json tool_def = {
    {"name", "annotate_code"},
    {"description", "Return improved labels and comments for disassembly addresses"},
    {"input_schema", {
      {"type", "object"},
      {"properties", {
        {"annotations", {
          {"type", "array"},
          {"items", {
            {"type", "object"},
            {"properties", {
              {"address", {
                {"type", "integer"},
                {"description", "Hex address (as decimal integer)"}
              }},
              {"label", {
                {"type", "string"},
                {"description", "Improved assembler label (empty to skip)"}
              }},
              {"comment", {
                {"type", "string"},
                {"description", "Inline comment ≤ 60 chars (empty to skip)"}
              }}
            }},
            {"required", json::array({"address", "label", "comment"})}
          }}
        }}
      }},
      {"required", json::array({"annotations"})}
    }}
  };

  json request_body = {
    {"model", model_},
    {"max_tokens", kMaxTokens},
    {"system", BuildSystemPrompt()},
    {"tools", json::array({tool_def})},
    {"tool_choice", {{"type", "any"}}},
    {"messages", json::array({
      {
        {"role", "user"},
        {"content", BuildUserMessage(chunk_context)}
      }
    })}
  };

  std::string body_str = request_body.dump();
  LOG_DEBUG("ClaudeAnalyzer: sending request (" +
            std::to_string(body_str.size()) + " bytes)");

  std::string resp_body = CallClaude(body_str);
  if (resp_body.empty()) return {};  // connection_failed_ already set by CallClaude

  return ParseToolResponse(resp_body);
}

// static
std::vector<LlmAnnotation> ClaudeAnalyzer::ParseToolResponse(
    const std::string& json_body) {
  std::vector<LlmAnnotation> results;

  try {
    auto resp = json::parse(json_body);

    // Find the tool_use content block
    auto& content = resp.at("content");
    for (const auto& block : content) {
      if (block.value("type", "") != "tool_use") continue;
      if (block.value("name", "") != "annotate_code") continue;

      auto& input = block.at("input");
      auto& annotations = input.at("annotations");

      for (const auto& ann : annotations) {
        LlmAnnotation la;
        la.address = ann.value("address", 0);
        la.label   = ann.value("label", "");
        la.comment = ann.value("comment", "");

        // Basic validation: skip fully empty annotations
        if (la.label.empty() && la.comment.empty()) continue;

        results.push_back(la);
      }
    }
  } catch (const json::exception& e) {
    LOG_WARNING(std::string("ClaudeAnalyzer: failed to parse API response: ") +
                e.what() + ". Continuing without LLM analysis.");
    return {};
  }

  LOG_INFO("ClaudeAnalyzer: received " + std::to_string(results.size()) +
           " annotation(s)");
  return results;
}

// ---------------------------------------------------------------------------
// Extended analysis — Passes 1, 2, 3
// ---------------------------------------------------------------------------

std::vector<LlmAnnotation> ClaudeAnalyzer::AnalyzeExtended(
    const core::Binary& binary,
    const core::AddressMap& address_map,
    const cpu::CpuPlugin* cpu) {

  std::vector<LlmAnnotation> all;

  // ------------------------------------------------------------------
  // Pass 1 — DATA-as-CODE detection
  // ------------------------------------------------------------------
  {
    auto candidates = DataCodeScanner::Scan(binary, address_map, cpu);
    LOG_INFO("ClaudeAnalyzer Pass1: " + std::to_string(candidates.size())
             + " DATA-as-CODE candidate(s)");

    if (!api_key_.empty() && !candidates.empty()) {
      // Ask Claude to confirm each candidate.
      for (const auto& cand : candidates) {
        // Build a focused prompt.
        std::string user_msg =
            "The following bytes are in a DATA region at address $"
            + [&] {
                std::ostringstream oss;
                oss << std::hex << std::uppercase << cand.start_address;
                return oss.str();
              }()
            + " but decode as valid 6502 instructions.\n"
              "Examine them and use the confirm_data_code tool.\n\n"
              "```\n" + cand.disasm_listing + "```";

        json tool_def = {
          {"name", "confirm_data_code"},
          {"description", "Confirm whether DATA-region bytes are likely code"},
          {"input_schema", {
            {"type", "object"},
            {"properties", {
              {"address", {
                {"type", "integer"},
                {"description", "Start address of the candidate region"}
              }},
              {"confidence", {
                {"type", "string"},
                {"enum", {"high", "medium", "low"}},
                {"description", "Confidence that bytes are executable code"}
              }},
              {"note", {
                {"type", "string"},
                {"description", "Brief note explaining the assessment"}
              }}
            }},
            {"required", json::array({"address", "confidence", "note"})}
          }}
        };

        json request_body = {
          {"model", model_},
          {"max_tokens", 512},
          {"system",
           "You are an expert 6502 disassembler. "
           "Assess whether a sequence of bytes in a DATA region is likely "
           "executable code rather than data."},
          {"tools", json::array({tool_def})},
          {"tool_choice", {{"type", "any"}}},
          {"messages", json::array({
            {{"role", "user"}, {"content", user_msg}}
          })}
        };

        std::string resp_body = CallClaude(request_body.dump());
        if (resp_body.empty()) {
          // Fallback: emit heuristic annotation without LLM confirmation.
          auto fallback = DataCodeScanner::BuildAnnotations({cand});
          all.insert(all.end(), fallback.begin(), fallback.end());
          continue;
        }

        try {
          auto resp = json::parse(resp_body);
          bool confirmed = false;
          std::string note;
          for (const auto& block : resp.at("content")) {
            if (block.value("type", "") != "tool_use") continue;
            if (block.value("name", "") != "confirm_data_code") continue;
            auto& inp = block.at("input");
            std::string conf = inp.value("confidence", "low");
            note = inp.value("note", "");
            confirmed = (conf == "high" || conf == "medium");
          }
          if (confirmed) {
            LlmAnnotation ann;
            ann.address = cand.start_address;
            ann.type = AnnotationType::POSSIBLE_CODE;
            ann.comment = "; *** POSSIBLE CODE — review and add to hints file ***";
            if (!note.empty()) ann.comment += " (" + note + ")";
            ann.comment += "\n" + cand.disasm_listing;
            all.push_back(std::move(ann));
          }
        } catch (const json::exception& e) {
          LOG_WARNING(std::string("ClaudeAnalyzer Pass1: JSON parse error: ") + e.what());
          auto fallback = DataCodeScanner::BuildAnnotations({cand});
          all.insert(all.end(), fallback.begin(), fallback.end());
        }
      }
    } else if (!candidates.empty()) {
      // No API key — emit heuristic annotations directly.
      auto anns = DataCodeScanner::BuildAnnotations(candidates);
      all.insert(all.end(), anns.begin(), anns.end());
    }
  }

  // ------------------------------------------------------------------
  // Pass 2 — Bytes-as-Strings (pure heuristic, no LLM needed)
  // ------------------------------------------------------------------
  {
    auto string_anns = StringScanner::Scan(binary, address_map);
    LOG_INFO("ClaudeAnalyzer Pass2: " + std::to_string(string_anns.size())
             + " string annotation(s)");
    all.insert(all.end(), string_anns.begin(), string_anns.end());
  }

  // ------------------------------------------------------------------
  // Pass 3 — Code Pattern Recognition
  // ------------------------------------------------------------------
  {
    // Gather all CODE-region instructions by disassembling the binary.
    // (We rely on the AddressMap to know what is CODE.)
    std::vector<core::Instruction> code_instructions;
    if (cpu) {
      for (const auto& seg : AllSegments(binary)) {
        const uint8_t* base = seg.data.data();
        const size_t seg_size = seg.data.size();
        const uint32_t seg_start = seg.load_address;
        const uint32_t seg_end = seg_start + static_cast<uint32_t>(seg_size);
        uint32_t addr = seg_start;
        while (addr < seg_end) {
          if (address_map.GetType(addr) != core::AddressType::CODE) {
            ++addr;
            continue;
          }
          size_t offset = addr - seg_start;
          auto inst = cpu->Disassemble(base + offset, seg_size - offset, addr);
          if (inst.bytes.empty()) { ++addr; continue; }
          code_instructions.push_back(inst);
          addr += static_cast<uint32_t>(inst.bytes.size());
        }
      }
    }

    auto candidates = CodePatternDetector::Detect(binary, address_map,
                                                   code_instructions);
    LOG_INFO("ClaudeAnalyzer Pass3: " + std::to_string(candidates.size())
             + " code pattern candidate(s)");

    if (!api_key_.empty() && !candidates.empty()) {
      for (const auto& cand : candidates) {
        std::string pattern_name = CodePatternDetector::PatternName(cand.pattern);
        std::string user_msg =
            "This 6502 subroutine starting at $"
            + [&] {
                std::ostringstream oss;
                oss << std::hex << std::uppercase << cand.start_address;
                return oss.str();
              }()
            + " appears to be a " + pattern_name + " routine.\n"
              "Use the annotate_pattern tool to give it an improved name, "
              "a one-line description, and up to 3 key instruction comments.\n\n"
              "```\n" + cand.disasm_listing + "```";

        json tool_def = {
          {"name", "annotate_pattern"},
          {"description", "Name and describe a recognised code pattern"},
          {"input_schema", {
            {"type", "object"},
            {"properties", {
              {"function_name", {
                {"type", "string"},
                {"description", "Short assembler identifier (≤15 chars)"}
              }},
              {"description", {
                {"type", "string"},
                {"description", "One-line description of what the routine does"}
              }},
              {"key_comments", {
                {"type", "array"},
                {"items", {
                  {"type", "object"},
                  {"properties", {
                    {"address", {{"type", "integer"}}},
                    {"comment", {{"type", "string"}}}
                  }},
                  {"required", json::array({"address", "comment"})}
                }},
                {"description", "Up to 3 key instructions to annotate"}
              }}
            }},
            {"required", json::array({"function_name", "description", "key_comments"})}
          }}
        };

        json request_body = {
          {"model", model_},
          {"max_tokens", 512},
          {"system",
           "You are an expert vintage assembly analyst. "
           "Identify and document classic 6502 subroutine patterns."},
          {"tools", json::array({tool_def})},
          {"tool_choice", {{"type", "any"}}},
          {"messages", json::array({
            {{"role", "user"}, {"content", user_msg}}
          })}
        };

        std::string resp_body = CallClaude(request_body.dump());
        if (resp_body.empty()) continue;

        try {
          auto resp = json::parse(resp_body);
          for (const auto& block : resp.at("content")) {
            if (block.value("type", "") != "tool_use") continue;
            if (block.value("name", "") != "annotate_pattern") continue;
            auto& inp = block.at("input");

            std::string fn_name = inp.value("function_name", "");
            std::string desc    = inp.value("description", "");

            if (!fn_name.empty() || !desc.empty()) {
              LlmAnnotation ann;
              ann.address = cand.start_address;
              ann.type = AnnotationType::CODE_PATTERN;
              ann.label = fn_name;
              ann.comment = desc.empty() ? "" : "; " + desc;
              all.push_back(std::move(ann));
            }

            // Per-instruction key comments
            if (inp.contains("key_comments")) {
              for (const auto& kc : inp.at("key_comments")) {
                LlmAnnotation kc_ann;
                kc_ann.address = kc.value("address", 0U);
                kc_ann.type = AnnotationType::CODE_PATTERN;
                kc_ann.comment = "; " + kc.value("comment", "");
                all.push_back(std::move(kc_ann));
              }
            }
          }
        } catch (const json::exception& e) {
          LOG_WARNING(std::string("ClaudeAnalyzer Pass3: JSON parse error: ") + e.what());
        }
      }
    } else if (!candidates.empty()) {
      // No API key — emit heuristic annotations for identified patterns.
      for (const auto& cand : candidates) {
        LlmAnnotation ann;
        ann.address = cand.start_address;
        ann.type = AnnotationType::CODE_PATTERN;
        std::string pattern_name = CodePatternDetector::PatternName(cand.pattern);
        ann.comment = "; Pattern: " + pattern_name;
        all.push_back(std::move(ann));
      }
    }
  }

  return all;
}

// ---------------------------------------------------------------------------
// Low-level helper
// ---------------------------------------------------------------------------

std::string ClaudeAnalyzer::CallClaude(const std::string& request_json) {
  // httplib::Client auto-selects SSL based on scheme ("https://" vs "http://")
  // when compiled with CPPHTTPLIB_OPENSSL_SUPPORT.
  httplib::Client cli(api_base_url_);
  cli.set_connection_timeout(30);
  cli.set_read_timeout(120);

  httplib::Headers headers = {
    {"x-api-key", api_key_},
    {"anthropic-version", kAnthropicVersion},
    {"content-type", "application/json"}
  };

  auto res = cli.Post(api_path_, headers, request_json, "application/json");

  if (!res) {
    connection_failed_ = true;
    LOG_ERROR("ClaudeAnalyzer: connection failed to " + api_base_url_ +
              " (" + httplib::to_string(res.error()) + "). "
              "Check network connectivity and --llm-url.");
    return {};
  }

  if (res->status != 200) {
    connection_failed_ = true;
    LOG_ERROR("ClaudeAnalyzer: API returned HTTP " +
              std::to_string(res->status) + ": " + res->body);
    return {};
  }

  return res->body;
}

}  // namespace llm
}  // namespace analysis
}  // namespace sourcerer
