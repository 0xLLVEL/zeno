#include "bridge.h"

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <deque>
#include <mutex>
#include <thread>

namespace zeno::bridge {
namespace {

constexpr const wchar_t* kInPipe = L"\\\\.\\pipe\\zeno_in";
constexpr const wchar_t* kOutPipe = L"\\\\.\\pipe\\zeno_out";

std::mutex g_out_mutex;
std::deque<std::string> g_out_queue;
HANDLE g_out_pipe = INVALID_HANDLE_VALUE;
std::atomic<bool> g_alive{false};
std::atomic<bool> g_linked{false};

HANDLE connect(const wchar_t* name, DWORD access) {
    for (;;) {
        HANDLE h = CreateFileW(name, access, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) return h;
        Sleep(250);
    }
}

bool write_all(HANDLE h, const char* data, DWORD len) {
    DWORD total = 0;
    while (total < len) {
        DWORD wrote = 0;
        if (!WriteFile(h, data + total, len - total, &wrote, nullptr) || wrote == 0) return false;
        total += wrote;
    }
    return true;
}

void writer_thread() {
    for (;;) {
        HANDLE h = connect(kOutPipe, GENERIC_WRITE);
        g_linked = true;

        std::string batch;
        for (;;) {
            {
                std::lock_guard lock(g_out_mutex);
                if (g_out_queue.empty()) {
                    batch.clear();
                } else {
                    for (auto& line : g_out_queue) {
                        batch += line;
                        batch += '\n';
                    }
                    g_out_queue.clear();
                }
            }
            if (!batch.empty()) {
                if (!write_all(h, batch.data(), (DWORD)batch.size())) {
                    CloseHandle(h);
                    g_linked = false;
                    std::lock_guard lock(g_out_mutex);
                    g_out_queue.emplace_front("[zeno] output pipe lost");
                    break;
                }
                batch.clear();
            }
            Sleep(20);
        }
    }
}

void reader_thread(std::function<void(std::string_view)> on_script) {
    for (;;) {
        HANDLE h = connect(kInPipe, GENERIC_READ);
        g_linked = true;

        std::string pending;
        char chunk[8192];

        for (;;) {
            DWORD read = 0;
            if (!ReadFile(h, chunk, sizeof(chunk), &read, nullptr) || read == 0) {
                g_linked = false;
                break;
            }
            pending.append(chunk, read);

            for (;;) {
                if (pending.size() < 4) break;
                uint32_t len = 0;
                memcpy(&len, pending.data(), 4);
                if (len > (16u << 20)) { // sanity cap: 16 MiB
                    out_err("script frame too large — dropping buffer");
                    pending.clear();
                    break;
                }
                if (pending.size() < 4u + len) break;

                std::string script = pending.substr(4, len);
                pending.erase(0, 4 + len);
                on_script(script);
            }
        }
        CloseHandle(h);
    }
}

void push(std::string_view prefix, std::string_view line) {
    std::string s;
    s.reserve(prefix.size() + line.size() + 1);
    s.append(prefix);
    s.append(line);
    std::lock_guard lock(g_out_mutex);
    g_out_queue.push_back(std::move(s));
    if (g_out_queue.size() > 4096) g_out_queue.pop_front();
}

} // namespace

void start(std::function<void(std::string_view)> on_script) {
    if (g_alive.exchange(true)) return;
    std::thread(writer_thread).detach();
    std::thread(reader_thread, std::move(on_script)).detach();
}

void out(std::string_view line) { push("", line); }
void out_err(std::string_view line) { push("[error] ", line); }
void out_warn(std::string_view line) { push("[warn] ", line); }

bool connected() { return g_linked.load(); }

} // namespace zeno::bridge
