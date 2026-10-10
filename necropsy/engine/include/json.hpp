#pragma once
#include <string>
#include <sstream>
#include <vector>
#include <cstdint>

namespace nc {
namespace json {

inline std::string escape(const std::string& s) {
    std::ostringstream o;
    for (char c : s) {
        switch (c) {
            case '"':  o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\n': o << "\\n";  break;
            case '\r': o << "\\r";  break;
            case '\t': o << "\\t";  break;
            default:
                if ((unsigned char)c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
                    o << buf;
                } else {
                    o << c;
                }
        }
    }
    return o.str();
}

inline std::string str(const std::string& s) {
    return "\"" + escape(s) + "\"";
}

inline std::string hex(uint64_t v) {
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)v);
    return std::string("\"") + buf + "\"";
}

inline std::string num(uint64_t v) {
    return std::to_string(v);
}

inline std::string boolean(bool b) {
    return b ? "true" : "false";
}

} // namespace json
} // namespace nc