#include "roblox.h"

#include <windows.h>
#include <psapi.h>

#include <fstream>
#include <mutex>
#include <sstream>
#include <unordered_map>
#include <vector>

namespace zeno::rbx {
namespace {

std::once_flag g_init_once;
bool g_ready = false;
std::unordered_map<std::string, uintptr_t> g_offsets;
std::unordered_map<std::string, std::string> g_patterns;
uintptr_t g_datamodel = 0;

std::string trim(std::string s) {
    size_t a = s.find_first_not_of(" \t\r\n\"");
    size_t b = s.find_last_not_of(" \t\r\n\"");
    if (a == std::string::npos) return {};
    return s.substr(a, b - a + 1);
}

// Deliberately tiny parser: the config file is flat and under our control.
void parse_config(const std::string& text) {
    std::istringstream in(text);
    std::string line;
    std::string section;

    while (std::getline(in, line)) {
        auto open = line.find('{');
        auto close = line.find('}');
        if (open != std::string::npos && close == std::string::npos) {
            auto pos = line.find('"');
            if (pos != std::string::npos) section = trim(line.substr(pos));
            continue;
        }
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;

        std::string key = trim(line.substr(0, colon));
        std::string value = trim(line.substr(colon + 1));
        if (!value.empty() && value.back() == ',') value.pop_back();
        if (key.empty() || value.empty()) continue;

        if (section == "offsets") {
            try {
                g_offsets[key] = static_cast<uintptr_t>(std::stoull(value, nullptr, 0));
            } catch (...) {
            }
        } else if (section == "patterns") {
            g_patterns[key] = value;
        }
    }
}

uintptr_t resolve_pattern_scan(std::string_view signature) {
    if (signature.empty()) return 0;

    struct Byte {
        uint8_t value;
        bool wildcard;
    };
    std::vector<Byte> bytes;
    std::istringstream in{std::string(signature)};
    std::string token;
    while (in >> token) {
        if (token == "?" || token == "??") {
            bytes.push_back({0, true});
        } else {
            bytes.push_back({static_cast<uint8_t>(std::stoul(token, nullptr, 16)), false});
        }
    }
    if (bytes.size() < 4) return 0;

    auto base = reinterpret_cast<const uint8_t*>(module_base());
    auto size = module_size();
    if (!base || size == 0) return 0;

    const size_t last = size - bytes.size();
    for (size_t i = 0; i < last; ++i) {
        bool hit = true;
        for (size_t j = 0; j < bytes.size(); ++j) {
            if (bytes[j].wildcard) continue;
            if (base[i + j] != bytes[j].value) {
                hit = false;
                break;
            }
        }
        if (hit) return module_base() + i;
    }
    return 0;
}

uintptr_t resolve_datamodel() {
    const auto pattern = g_patterns.find("DataModelScan");
    if (pattern == g_patterns.end()) return 0;

    uintptr_t hit = resolve_pattern_scan(pattern->second);
    if (!hit) return 0;

    // mov rax, [rip+disp32]; disp is at hit+3
    int32_t disp = read_or<int32_t>(hit + 3, 0);
    uintptr_t target = hit + 7 + static_cast<intptr_t>(disp);
    return read_or<uintptr_t>(target, 0);
}

} // namespace

bool init() {
    std::call_once(g_init_once, [] {
        char module_path[MAX_PATH]{};
        HMODULE self = GetModuleHandleW(nullptr);
        GetModuleFileNameA(self, module_path, MAX_PATH);

        std::string path(module_path);
        auto slash = path.find_last_of("\\/");
        std::string dir = slash == std::string::npos ? "." : path.substr(0, slash);
        std::string config = dir + "\\zeno_offsets.json";

        std::ifstream file(config);
        if (file) {
            std::stringstream buffer;
            buffer << file.rdbuf();
            parse_config(buffer.str());
        }

        g_datamodel = resolve_datamodel();
        g_ready = true;
    });
    return g_ready;
}

bool ready() { return g_ready; }

uintptr_t module_base() {
    return reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
}

size_t module_size() {
    MODULEINFO info{};
    if (GetModuleInformation(GetCurrentProcess(), GetModuleHandleW(nullptr), &info, sizeof(info))) {
        return info.SizeOfImage;
    }
    return 0;
}

uintptr_t offset(std::string_view key) {
    auto it = g_offsets.find(std::string(key));
    return it == g_offsets.end() ? 0 : it->second;
}

std::string pattern(std::string_view key) {
    auto it = g_patterns.find(std::string(key));
    return it == g_patterns.end() ? std::string{} : it->second;
}

uintptr_t find_pattern(std::string_view signature) {
    return resolve_pattern_scan(signature);
}

uintptr_t datamodel() { return g_datamodel; }

} // namespace zeno::rbx
