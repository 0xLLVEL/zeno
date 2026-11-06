#pragma once
#include <windows.h>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace zeno::rbx {

bool init();
bool ready();

uintptr_t module_base();
size_t module_size();

uintptr_t offset(std::string_view key);
std::string pattern(std::string_view key);

uintptr_t find_pattern(std::string_view signature);

template <typename T>
bool read(uintptr_t address, T& out) {
    __try {
        out = *reinterpret_cast<T*>(address);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

template <typename T>
bool write(uintptr_t address, const T& value) {
    __try {
        *reinterpret_cast<T*>(address) = value;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

template <typename T>
T read_or(uintptr_t address, T fallback) {
    T v{};
    return read(address, v) ? v : fallback;
}

// Resolved lazily; null until init() succeeds.
uintptr_t datamodel();

// The client build this process is, and whether the offset pack agrees.
std::string client();
bool client_matches();

// Instance graph. Every accessor is SEH-guarded and returns empty/0 on a bad
// pointer instead of taking the client down.
uintptr_t instance_parent(uintptr_t instance);
std::string instance_name(uintptr_t instance);
std::string instance_class_name(uintptr_t instance);
std::vector<uintptr_t> instance_children(uintptr_t instance);
uintptr_t find_child(uintptr_t parent, std::string_view name);

// One-line, human-readable snapshot of everything resolved so far. Safe to
// call before init(); it just reports zeros.
std::string describe();

} // namespace zeno::rbx
