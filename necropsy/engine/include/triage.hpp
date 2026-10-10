#pragma once
#include "minidump.hpp"
#include <string>
#include <vector>

namespace nc {

enum class Verdict {
    EXPLOITABLE,
    PROBABLY_EXPLOITABLE,
    UNKNOWN,
    NOT_EXPLOITABLE,
};

const char* verdict_name(Verdict v);

struct Finding {
    std::string rule;
    std::string severity;  // critical / high / medium / low / info
    std::string detail;
};

struct TriageResult {
    std::string path;
    Verdict verdict = Verdict::UNKNOWN;
    int     score = 0;

    uint32_t    exception_code = 0;
    std::string exception_name = "UNKNOWN";
    std::string access_type;
    uint64_t    faulting_address = 0;
    std::string faulting_module;
    std::string faulting_frame;
    uint64_t    instruction_pointer = 0;
    uint64_t    stack_pointer = 0;
    Context     context;
    bool        has_context = false;

    std::vector<Finding> findings;
    std::string rationale;

    void add(const std::string& rule, const std::string& sev, const std::string& detail);
};

TriageResult triage(const Minidump& md);

} // namespace nc