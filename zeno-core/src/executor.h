#pragma once
#include <string>
#include <string_view>

struct lua_State;

namespace zeno {

class Executor {
public:
    static Executor& instance();

    bool init();
    void shutdown();

    void execute(std::string_view source);

    // Creates a Lua thread from [function, args...] on `caller`'s stack.
    // Returns the registry ref; the thread starts after delay_ms.
    int spawn_from(lua_State* caller, long long delay_ms);

private:
    Executor() = default;

    void worker();
    void run_script(const std::string& source);
    void schedule(int thread_ref, long long delay_ms, int nargs);
    void resume(int thread_ref, int nargs);
    void settle(int status, lua_State* thread, int ref, const char* chunk);

    struct Impl;
    Impl* d = nullptr;
};

void install_api(lua_State* L);

} // namespace zeno
