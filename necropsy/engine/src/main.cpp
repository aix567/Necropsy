#include "minidump.hpp"
#include "triage.hpp"
#include "json.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

using namespace nc;

static std::string read_all(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static std::string dump_to_json(const Minidump& md, const TriageResult& t) {
    using json::str;
    using json::hex;
    using json::num;
    std::ostringstream o;
    o << "{";
    o << "\"path\":"          << str(md.path) << ",";
    o << "\"size\":"          << num(md.size) << ",";
    o << "\"timestamp\":"     << num(md.timestamp) << ",";
    o << "\"module_count\":"  << num(md.modules.size()) << ",";
    o << "\"verdict\":"       << str(verdict_name(t.verdict)) << ",";
    o << "\"score\":"         << num(t.score) << ",";
    o << "\"exception_code\":"   << hex(t.exception_code) << ",";
    o << "\"exception_name\":"   << str(t.exception_name) << ",";
    o << "\"access_type\":"      << str(t.access_type) << ",";
    o << "\"faulting_address\":" << hex(t.faulting_address) << ",";
    o << "\"faulting_module\":"  << str(t.faulting_module) << ",";
    o << "\"faulting_frame\":"   << str(t.faulting_frame) << ",";
    o << "\"instruction_pointer\":" << hex(t.instruction_pointer) << ",";
    o << "\"stack_pointer\":"    << hex(t.stack_pointer) << ",";
    o << "\"rationale\":"        << str(t.rationale) << ",";

    o << "\"registers\":{";
    if (t.has_context) {
        const auto& c = t.context;
        o << "\"rax\":" << hex(c.rax) << ","
          << "\"rcx\":" << hex(c.rcx) << ","
          << "\"rdx\":" << hex(c.rdx) << ","
          << "\"rbx\":" << hex(c.rbx) << ","
          << "\"rsp\":" << hex(c.rsp) << ","
          << "\"rbp\":" << hex(c.rbp) << ","
          << "\"rsi\":" << hex(c.rsi) << ","
          << "\"rdi\":" << hex(c.rdi) << ","
          << "\"r8\":"  << hex(c.r8)  << ","
          << "\"r9\":"  << hex(c.r9)  << ","
          << "\"r10\":" << hex(c.r10) << ","
          << "\"r11\":" << hex(c.r11) << ","
          << "\"r12\":" << hex(c.r12) << ","
          << "\"r13\":" << hex(c.r13) << ","
          << "\"r14\":" << hex(c.r14) << ","
          << "\"r15\":" << hex(c.r15) << ","
          << "\"rip\":" << hex(c.rip);
    }
    o << "},";

    o << "\"findings\":[";
    for (size_t i = 0; i < t.findings.size(); i++) {
        const auto& f = t.findings[i];
        if (i) o << ",";
        o << "{\"rule\":" << str(f.rule)
          << ",\"severity\":" << str(f.severity)
          << ",\"detail\":"   << str(f.detail) << "}";
    }
    o << "]}";
    return o.str();
}

static void print_text(const Minidump& md, const TriageResult& t) {
    std::cout << "[+] " << md.path << "\n";
    std::cout << "    size: " << md.size << " bytes\n";
    std::cout << "    timestamp: " << md.timestamp << "\n";
    if (md.sysinfo) {
        std::cout << "    processor: " << md.sysinfo->arch_name()
                  << ", " << (int)md.sysinfo->number_of_processors << " cores\n";
        std::cout << "    os: " << md.sysinfo->major_version << "."
                  << md.sysinfo->minor_version << "."
                  << md.sysinfo->build_number << "\n";
    }
    std::cout << "    modules: " << md.modules.size() << "\n\n";

    std::cout << "[*] exception\n";
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%08x", t.exception_code);
    std::cout << "    code:     " << buf << " (" << t.exception_name << ")\n";
    if (!t.access_type.empty()) std::cout << "    access:   " << t.access_type << "\n";
    snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)t.faulting_address);
    std::cout << "    address:  " << buf << "\n\n";

    if (t.has_context) {
        std::cout << "[*] registers\n";
        const auto& c = t.context;
        auto pr = [](const char* n, uint64_t v) {
            char b[32];
            snprintf(b, sizeof(b), "0x%016llx", (unsigned long long)v);
            std::cout << "    " << n << "  " << b << "\n";
        };
        pr("rip", c.rip); pr("rsp", c.rsp); pr("rbp", c.rbp);
        pr("rax", c.rax); pr("rbx", c.rbx); pr("rcx", c.rcx); pr("rdx", c.rdx);
        std::cout << "\n";
    }

    std::cout << "[*] verdict: " << verdict_name(t.verdict)
              << " (score " << t.score << ")\n";
    if (!t.faulting_module.empty())
        std::cout << "    module: " << t.faulting_module << "\n";
    if (!t.faulting_frame.empty())
        std::cout << "    frame:  " << t.faulting_frame << "\n";

    if (!t.findings.empty()) {
        std::cout << "\n[*] findings\n";
        for (const auto& f : t.findings) {
            std::cout << "    [" << f.severity << "] "
                      << f.rule << " — " << f.detail << "\n";
        }
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: necropsy-engine <dump.dmp> [--json|--text]\n";
        return 1;
    }

    std::string dump_path = argv[1];
    std::string fmt = "text";
    for (int i = 2; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--json") fmt = "json";
        else if (a == "--text") fmt = "text";
    }

    Minidump md;
    if (!md.load(dump_path)) {
        std::cerr << "[!] failed to load " << dump_path << "\n";
        return 2;
    }

    TriageResult t = triage(md);

    if (fmt == "json") {
        std::cout << dump_to_json(md, t) << "\n";
    } else {
        print_text(md, t);
    }
    return 0;
}