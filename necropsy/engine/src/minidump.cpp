#include "minidump.hpp"
#include <fstream>
#include <cstring>
#include <algorithm>

namespace nc {

static constexpr uint32_t MDMP_SIGNATURE = 0x504D444D;

uint8_t  Minidump::u8(size_t o)  const { return data_[o]; }
uint16_t Minidump::u16(size_t o) const { uint16_t v; memcpy(&v, &data_[o], 2); return v; }
uint32_t Minidump::u32(size_t o) const { uint32_t v; memcpy(&v, &data_[o], 4); return v; }
uint64_t Minidump::u64(size_t o) const { uint64_t v; memcpy(&v, &data_[o], 8); return v; }

std::string Module::short_name() const {
    auto pos = name.find_last_of("\\/");
    return pos == std::string::npos ? name : name.substr(pos + 1);
}

std::string SystemInfo::arch_name() const {
    switch (processor_arch) {
        case 0:  return "x86";
        case 5:  return "ARM";
        case 6:  return "IA64";
        case 9:  return "x64";
        case 12: return "ARM64";
        default: return "unknown";
    }
}

std::string Minidump::read_utf16_string(size_t rva) const {
    if (rva + 4 > data_.size()) return "";
    uint32_t len_bytes = u32(rva);
    if (rva + 4 + len_bytes > data_.size()) return "";
    std::string out;
    out.reserve(len_bytes / 2);
    for (uint32_t i = 0; i + 1 < len_bytes; i += 2) {
        char16_t c;
        memcpy(&c, &data_[rva + 4 + i], 2);
        if (c < 0x80) out.push_back((char)c);
        else if (c < 0x800) {
            out.push_back((char)(0xC0 | (c >> 6)));
            out.push_back((char)(0x80 | (c & 0x3F)));
        } else {
            out.push_back((char)(0xE0 | (c >> 12)));
            out.push_back((char)(0x80 | ((c >> 6) & 0x3F)));
            out.push_back((char)(0x80 | (c & 0x3F)));
        }
    }
    return out;
}

void Minidump::parse_context(const uint8_t* b, size_t len, Context& c) {
    if (len < 0x100) return;
    memcpy(&c.context_flags, b + 0x30, 4);
    memcpy(&c.eflags,        b + 0x44, 4);
    memcpy(&c.rax,           b + 0x78, 8);
    memcpy(&c.rcx,           b + 0x80, 8);
    memcpy(&c.rdx,           b + 0x88, 8);
    memcpy(&c.rbx,           b + 0x90, 8);
    memcpy(&c.rsp,           b + 0x98, 8);
    memcpy(&c.rbp,           b + 0xA0, 8);
    memcpy(&c.rsi,           b + 0xA8, 8);
    memcpy(&c.rdi,           b + 0xB0, 8);
    memcpy(&c.r8,            b + 0xB8, 8);
    memcpy(&c.r9,            b + 0xC0, 8);
    memcpy(&c.r10,           b + 0xC8, 8);
    memcpy(&c.r11,           b + 0xD0, 8);
    memcpy(&c.r12,           b + 0xD8, 8);
    memcpy(&c.r13,           b + 0xE0, 8);
    memcpy(&c.r14,           b + 0xE8, 8);
    memcpy(&c.r15,           b + 0xF0, 8);
    memcpy(&c.rip,           b + 0xF8, 8);
}

void Minidump::parse_modules(size_t rva) {
    if (rva + 4 > data_.size()) return;
    uint32_t count = u32(rva);
    size_t p = rva + 4;
    for (uint32_t i = 0; i < count; i++) {
        if (p + 108 > data_.size()) break;
        Module m;
        m.base = u64(p);
        m.size = u32(p + 8);
        uint32_t name_rva = u32(p + 20);
        m.name = read_utf16_string(name_rva);
        modules.push_back(std::move(m));
        p += 108; // base(8)+size(4)+checksum(4)+ts(4)+name_rva(4)+verinfo(52)+cv(8)+misc(8)+res0(8)+res1(8)
    }
}

void Minidump::parse_exception(size_t rva) {
    if (rva + 168 > data_.size()) return;
    faulting_thread_id = u32(rva);
    ExceptionRecord ex;
    ex.code    = u32(rva + 8);
    ex.flags   = u32(rva + 12);
    ex.address = u64(rva + 24);
    uint32_t nparams = u32(rva + 32);
    size_t pp = rva + 40;
    for (uint32_t i = 0; i < nparams && i < 15; i++) {
        ex.params.push_back(u64(pp + i * 8));
    }
    exception = ex;

    // thread context follows: size(4) + rva(4)
    uint32_t ctx_size = u32(rva + 160);
    uint32_t ctx_rva  = u32(rva + 164);
    if (ctx_size && ctx_rva && ctx_rva + ctx_size <= data_.size()) {
        Thread t;
        t.tid = faulting_thread_id;
        parse_context(&data_[ctx_rva], ctx_size, t.context);
        t.has_context = true;
        threads.push_back(std::move(t));
    }
}

void Minidump::parse_sysinfo(size_t rva) {
    if (rva + 56 > data_.size()) return;
    SystemInfo si;
    si.processor_arch         = u16(rva);
    si.number_of_processors   = u8(rva + 6);
    si.major_version          = u32(rva + 8);
    si.minor_version          = u32(rva + 12);
    si.build_number           = u32(rva + 16);
    uint32_t csd_rva          = u32(rva + 24);
    if (csd_rva) si.csd_version = read_utf16_string(csd_rva);
    sysinfo = si;
}

bool Minidump::load(const std::string& p) {
    path = p;
    std::ifstream f(p, std::ios::binary | std::ios::ate);
    if (!f) return false;
    size_t sz = (size_t)f.tellg();
    f.seekg(0);
    data_.resize(sz);
    f.read(reinterpret_cast<char*>(data_.data()), sz);
    size = sz;

    if (sz < 32) return false;
    if (u32(0) != MDMP_SIGNATURE) return false;

    uint32_t num_streams = u32(8);
    uint32_t dir_rva     = u32(12);
    timestamp            = u32(16);
    flags                = u64(20);

    size_t dp = dir_rva;
    for (uint32_t i = 0; i < num_streams; i++) {
        if (dp + 12 > data_.size()) break;
        uint32_t type = u32(dp);
        uint32_t rva  = u32(dp + 8);
        switch (type) {
            case 4:  parse_modules(rva);   break;
            case 6:  parse_exception(rva); break;
            case 7:  parse_sysinfo(rva);   break;
            default: break;
        }
        dp += 12;
    }
    return true;
}

const Module* Minidump::find_module(uint64_t addr) const {
    for (const auto& m : modules) {
        if (m.base <= addr && addr < m.base + m.size) return &m;
    }
    return nullptr;
}

std::string Minidump::rva_to_name(uint64_t addr) const {
    const Module* m = find_module(addr);
    if (!m) {
        char buf[32];
        snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)addr);
        return buf;
    }
    char buf[64];
    snprintf(buf, sizeof(buf), "+0x%llx", (unsigned long long)(addr - m->base));
    return m->short_name() + buf;
}

} // namespace nc