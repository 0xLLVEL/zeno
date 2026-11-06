#pragma once
#include <cstdint>
#include <string>
#include <string_view>

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

} // namespace zeno::rbx
