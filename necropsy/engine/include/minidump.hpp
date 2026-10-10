#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <optional>

namespace nc {

struct Module {
    uint64_t base;
    uint32_t size;
    std::string name;
    std::string short_name() const;
};

struct ExceptionRecord {
    uint32_t code;
    uint32_t flags;
    uint64_t address;
    std::vector<uint64_t> params;
};

struct Context {
    uint64_t rax = 0, rcx = 0, rdx = 0, rbx = 0;
    uint64_t rsp = 0, rbp = 0, rsi = 0, rdi = 0;
    uint64_t r8 = 0, r9 = 0, r10 = 0, r11 = 0;
    uint64_t r12 = 0, r13 = 0, r14 = 0, r15 = 0;
    uint64_t rip = 0;
    uint32_t eflags = 0;
    uint32_t context_flags = 0;
};

struct SystemInfo {
    uint16_t processor_arch = 0;
    uint8_t  number_of_processors = 0;
    uint32_t major_version = 0;
    uint32_t minor_version = 0;
    uint32_t build_number = 0;
    std::string csd_version;
    std::string arch_name() const;
};

struct Thread {
    uint32_t tid = 0;
    Context  context;
    bool     has_context = false;
};

class Minidump {
public:
    std::string path;
    uint64_t    size = 0;
    uint32_t    timestamp = 0;
    uint64_t    flags = 0;

    std::optional<ExceptionRecord> exception;
    uint32_t faulting_thread_id = 0;

    std::vector<Thread> threads;
    std::vector<Module> modules;
    std::optional<SystemInfo> sysinfo;

    bool load(const std::string& path);
    const Module* find_module(uint64_t addr) const;
    std::string rva_to_name(uint64_t addr) const;

private:
    std::vector<uint8_t> data_;

    uint16_t u16(size_t off) const;
    uint32_t u32(size_t off) const;
    uint64_t u64(size_t off) const;
    uint8_t  u8(size_t off) const;

    void parse_modules(size_t rva);
    void parse_exception(size_t rva);
    void parse_sysinfo(size_t rva);
    void parse_context(const uint8_t* blob, size_t len, Context& out);
    std::string read_utf16_string(size_t rva) const;
};

} // namespace nc