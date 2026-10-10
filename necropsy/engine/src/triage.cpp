#include "triage.hpp"
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <sstream>

namespace nc {

const char* verdict_name(Verdict v) {
    switch (v) {
        case Verdict::EXPLOITABLE:          return "EXPLOITABLE";
        case Verdict::PROBABLY_EXPLOITABLE: return "PROBABLY_EXPLOITABLE";
        case Verdict::UNKNOWN:              return "UNKNOWN";
        case Verdict::NOT_EXPLOITABLE:      return "NOT_EXPLOITABLE";
    }
    return "UNKNOWN";
}

static const std::unordered_map<uint32_t, const char*> EXC_NAMES = {
    {0xC0000005, "ACCESS_VIOLATION"},
    {0xC0000006, "IN_PAGE_ERROR"},
    {0xC000001D, "ILLEGAL_INSTRUCTION"},
    {0xC0000025, "NONCONTINUABLE_EXCEPTION"},
    {0xC000008C, "ARRAY_BOUNDS_EXCEEDED"},
    {0xC0000094, "INTEGER_DIVIDE_BY_ZERO"},
    {0xC0000095, "INTEGER_OVERFLOW"},
    {0xC0000096, "PRIVILEGED_INSTRUCTION"},
    {0xC00000FD, "STACK_OVERFLOW"},
    {0xC0000409, "STACK_BUFFER_OVERRUN"},
    {0xC0000374, "HEAP_CORRUPTION"},
    {0xC0000602, "FAIL_FAST"},
    {0x80000003, "BREAKPOINT"},
};

static const std::unordered_set<std::string> HIGH_VALUE = {
    "mpengine", "mpclient", "mpcommu", "wdfilter", "mpksldrv",
    "ntoskrnl", "ntdll", "kernelbase", "msxml", "ole32",
    "jscript", "vbscript", "chakra", "winhttp", "ws2_32",
};

static const std::unordered_set<uint64_t> POISON = {
    0x4141414141414141ULL, 0x4242424242424242ULL, 0x4343434343434343ULL,
    0xdeadbeefdeadbeefULL, 0xcafebabecafebabeULL, 0xffffffffffffffffULL,
    0x41414141ULL, 0x42424242ULL, 0xdeadbeefULL, 0xcafebabeULL,
};

static bool is_user(uint64_t a)   { return a > 0 && a < 0x00007FFFFFFFFFFFULL; }
static bool is_kernel(uint64_t a) { return a >= 0xFFFF800000000000ULL; }
static bool is_null_near(uint64_t a) { return a < 0x10000; }
static bool is_poison(uint64_t a) { return POISON.count(a) > 0; }

void TriageResult::add(const std::string& r, const std::string& s, const std::string& d) {
    findings.push_back({r, s, d});
}

TriageResult triage(const Minidump& md) {
    TriageResult t;
    t.path = md.path;

    if (!md.exception) {
        t.rationale = "no exception record";
        return t;
    }

    const auto& ex = *md.exception;
    t.exception_code = ex.code;
    auto it = EXC_NAMES.find(ex.code);
    t.exception_name = (it != EXC_NAMES.end()) ? it->second : "UNKNOWN";
    t.faulting_address = ex.address;
    t.instruction_pointer = ex.address;

    if (ex.code == 0xC0000005 && ex.params.size() >= 2) {
        uint64_t flag = ex.params[0];
        t.faulting_address = ex.params[1];
        if      (flag == 0) t.access_type = "READ";
        else if (flag == 1) t.access_type = "WRITE";
        else if (flag == 8) t.access_type = "EXECUTE";
    }

    for (const auto& th : md.threads) {
        if (th.tid == md.faulting_thread_id && th.has_context) {
            t.context = th.context;
            t.has_context = true;
            t.instruction_pointer = th.context.rip;
            t.stack_pointer = th.context.rsp;
            break;
        }
    }

    if (const Module* m = md.find_module(t.instruction_pointer)) {
        t.faulting_module = m->short_name();
    }
    t.faulting_frame = md.rva_to_name(t.instruction_pointer);

    // rules
    if (ex.code == 0xC0000005) {
        if (t.faulting_address && t.instruction_pointer == t.faulting_address) {
            t.verdict = Verdict::EXPLOITABLE;
            t.score += 50;
            t.add("rip-control", "critical",
                  "RIP == faulting address - instruction pointer control");
        }
        if (is_poison(t.faulting_address)) {
            t.verdict = Verdict::EXPLOITABLE;
            t.score += 45;
            t.add("poison-ptr", "critical",
                  "faulting address matches poison pattern");
        }
        if (t.access_type == "WRITE") {
            if (is_null_near(t.faulting_address)) {
                if (t.verdict == Verdict::UNKNOWN) t.verdict = Verdict::NOT_EXPLOITABLE;
                t.add("write-null", "low", "write AV near null");
            } else if (is_user(t.faulting_address)) {
                if (t.verdict != Verdict::EXPLOITABLE) t.verdict = Verdict::PROBABLY_EXPLOITABLE;
                t.score += 30;
                t.add("write-av-user", "high", "write AV at user-controlled address");
            } else if (is_kernel(t.faulting_address)) {
                if (t.verdict != Verdict::EXPLOITABLE) t.verdict = Verdict::PROBABLY_EXPLOITABLE;
                t.score += 25;
                t.add("write-av-kernel", "high", "write AV at kernel address");
            }
        } else if (t.access_type == "READ") {
            if (is_null_near(t.faulting_address)) {
                if (t.verdict == Verdict::UNKNOWN) t.verdict = Verdict::NOT_EXPLOITABLE;
                t.add("read-null", "low", "read AV near null");
            } else if (is_user(t.faulting_address)) {
                t.score += 15;
                t.add("read-av-user", "medium", "read AV at user range");
            }
        }
    } else if (ex.code == 0xC00000FD) {
        t.verdict = Verdict::PROBABLY_EXPLOITABLE;
        t.score += 35;
        t.add("stack-overflow", "high", "stack overflow");
    } else if (ex.code == 0xC0000374) {
        t.verdict = Verdict::EXPLOITABLE;
        t.score += 45;
        t.add("heap-corruption", "critical", "heap corruption");
    } else if (ex.code == 0xC0000409) {
        t.verdict = Verdict::PROBABLY_EXPLOITABLE;
        t.score += 30;
        t.add("gs-canary", "high", "stack buffer overrun (/GS)");
    } else if (ex.code == 0xC0000094 || ex.code == 0xC0000095) {
        t.verdict = Verdict::NOT_EXPLOITABLE;
        t.add("arith", "low", "arithmetic exception");
    } else if (ex.code == 0xC000001D) {
        t.verdict = Verdict::UNKNOWN;
        t.score += 10;
        t.add("ill-inst", "medium", "illegal instruction");
    } else {
        t.add("unknown-code", "info", "unhandled exception code");
    }

    if (t.has_context) {
        uint64_t rip = t.context.rip;
        if (rip && !is_user(rip) && !is_kernel(rip)) {
            t.verdict = Verdict::EXPLOITABLE;
            t.score += 40;
            t.add("rip-non-canonical", "critical", "RIP non-canonical");
        }
    }

    std::string fm_lower = t.faulting_module;
    std::transform(fm_lower.begin(), fm_lower.end(), fm_lower.begin(), ::tolower);
    for (const auto& hv : HIGH_VALUE) {
        if (fm_lower.find(hv) != std::string::npos) {
            t.score += 10;
            t.add("high-value-module", "info", "faulting module is high-value");
            break;
        }
    }

    std::ostringstream rs;
    for (size_t i = 0; i < t.findings.size(); i++) {
        if (i) rs << "; ";
        rs << t.findings[i].detail;
    }
    t.rationale = rs.str();
    return t;
}

} // namespace nc