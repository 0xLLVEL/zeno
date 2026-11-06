#include "executor.h"

#include "bridge.h"
#include "roblox.h"

#include "lua.h"
#include "lualib.h"
#include "luacode.h"
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

namespace zeno {
namespace {

using Clock = std::chrono::steady_clock;

long long now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               Clock::now().time_since_epoch())
        .count();
}

struct Pending {
    int ref;
    long long due;
    int nargs;
};

const char* kPrelude = R"LUAU(
-- Zeno prelude: sandbox + roblox-flavoured globals

local __print = __zeno_print
local __warn = __zeno_warn

function print(...)
    __print(...)
end

function warn(...)
    __warn(...)
end

task = task or {}
function task.wait(t)
    t = t or 0
    if t > 0 then
        coroutine.yield(t)
    end
end

function task.spawn(fn, ...)
    return __zeno_spawn(fn, ...)
end

function task.defer(fn, ...)
    return __zeno_spawn(fn, ...)
end

function task.delay(t, fn, ...)
    return __zeno_delay(t, fn, ...)
end

wait = task.wait
spawn = task.spawn
delay = task.delay
tick = function() return __zeno_tick() end
time = function() return __zeno_tick() end

local function make_instance(class)
    local self = {
        ClassName = class,
        Name = class,
        Parent = nil,
        _children = {},
        _props = {},
    }

    function self:Destroy()
        if self.Parent and self.Parent._children then
            local list = self.Parent._children
            for i = #list, 1, -1 do
                if list[i] == self then table.remove(list, i) end
            end
        end
        self.Parent = nil
    end

    function self:Clone()
        return make_instance(self.ClassName)
    end

    function self:GetChildren()
        local out = {}
        for i, child in ipairs(self._children) do out[i] = child end
        return out
    end

    function self:FindFirstChild(name)
        for _, child in ipairs(self._children) do
            if child.Name == name then return child end
        end
        return nil
    end

    function self:WaitForChild(name, timeout)
        local elapsed = 0
        while elapsed < (timeout or 5) do
            local found = self:FindFirstChild(name)
            if found then return found end
            task.wait(0.05)
            elapsed += 0.05
        end
        return nil
    end

    function self:IsA(class)
        return self.ClassName == class
    end

    return setmetatable(self, {
        __index = function(t, k)
            local prop = rawget(t, "_props")
            if prop and prop[k] ~= nil then return prop[k] end
            return nil
        end,
        __newindex = function(t, k, v)
            if k == "Parent" then
                rawset(t, "Parent", v)
                if v and v._children then table.insert(v._children, t) end
                return
            end
            rawget(t, "_props")[k] = v
        end,
    })
end

Instance = {}
function Instance.new(class)
    return make_instance(class)
end

-- offline services; replaced by the native proxy when attached
local services = {}
local service_names = {
    "Players", "Workspace", "Lighting", "ReplicatedStorage", "ReplicatedFirst",
    "ServerStorage", "ServerScriptService", "StarterGui", "StarterPack",
    "SoundService", "RunService", "UserInputService", "TweenService",
    "HttpService", "MarketplaceService", "TeleportService", "Chat",
    "VirtualUser", "VirtualInputManager", "CoreGui",
}

game = setmetatable({}, {
    __index = function(_, k)
        if k == "GetService" then
            return function(_, name)
                if not services[name] then
                    services[name] = make_instance(name)
                end
                return services[name]
            end
        end
        if k == "Name" then return "Roblox" end
        if k == "PlaceId" then return 0 end
        if k == "GameId" then return 0 end
        if k == "Workspace" then return workspace end
        return nil
    end,
})

for _, name in ipairs(service_names) do
    services[name] = make_instance(name)
end

workspace = services["Workspace"]
script = make_instance("Script")
shared = {}
)LUAU";

int l_print(lua_State* L) {
    int n = lua_gettop(L);
    std::string line;
    for (int i = 1; i <= n; ++i) {
        size_t len = 0;
        const char* text = luaL_tolstring(L, i, &len);
        if (!text) continue;
        if (i > 1) line += ' ';
        line.append(text, len);
        lua_pop(L, 1);
    }
    bridge::out(line);
    return 0;
}

int l_warn(lua_State* L) {
    int n = lua_gettop(L);
    std::string line;
    for (int i = 1; i <= n; ++i) {
        size_t len = 0;
        const char* text = luaL_tolstring(L, i, &len);
        if (!text) continue;
        if (i > 1) line += ' ';
        line.append(text, len);
        lua_pop(L, 1);
    }
    bridge::out_warn(line);
    return 0;
}

int l_tick(lua_State* L) {
    static const auto start = std::chrono::steady_clock::now();
    const auto now = std::chrono::steady_clock::now();
    const double seconds = std::chrono::duration<double>(now - start).count();
    lua_pushnumber(L, seconds);
    return 1;
}

int l_capability(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    lua_pushboolean(L, zeno::rbx::ready() && name && std::string_view(name) == "attached");
    return 1;
}

int l_read_ptr(lua_State* L) {
    auto address = static_cast<uintptr_t>(luaL_checknumber(L, 1));
    lua_pushnumber(L, static_cast<double>(zeno::rbx::read_or<uintptr_t>(address, 0)));
    return 1;
}

int l_datamodel(lua_State* L) {
    lua_pushnumber(L, static_cast<double>(zeno::rbx::datamodel()));
    return 1;
}

int l_spawn(lua_State* L) {
    Executor::instance().spawn_from(L, 0);
    return 0;
}

int l_delay(lua_State* L) {
    const double seconds = luaL_checknumber(L, 1);
    lua_remove(L, 1);
    Executor::instance().spawn_from(L, static_cast<long long>(seconds * 1000.0));
    return 0;
}

} // namespace

void install_api(lua_State* L) {
    using namespace zeno::rbx;

    lua_register(L, "__zeno_print", l_print);
    lua_register(L, "__zeno_warn", l_warn);
    lua_register(L, "__zeno_tick", l_tick);
    lua_register(L, "__zeno_spawn", l_spawn);
    lua_register(L, "__zeno_delay", l_delay);

    lua_register(L, "zeno_capability", l_capability);
    lua_register(L, "zeno_read_ptr", l_read_ptr);
    lua_register(L, "zeno_datamodel", l_datamodel);

    lua_newtable(L);
    int idx = 1;
    auto set = [&](const char* k, lua_Number v) {
        lua_pushstring(L, k);
        lua_pushnumber(L, v);
        lua_rawset(L, -3);
    };
    set("DataModel", static_cast<lua_Number>(datamodel()));
    set("Workspace", static_cast<lua_Number>(offset("DataModel.Workspace")));
    set("GameId", static_cast<lua_Number>(offset("DataModel.GameId")));
    set("PlaceId", static_cast<lua_Number>(offset("DataModel.PlaceId")));
    set("ScriptContext", static_cast<lua_Number>(offset("DataModel.ScriptContext")));
    set("Name", static_cast<lua_Number>(offset("Instance.Name")));
    set("ChildrenStart", static_cast<lua_Number>(offset("Instance.ChildrenStart")));
    set("ClassDescriptor", static_cast<lua_Number>(offset("Instance.ClassDescriptor")));
    set("base", static_cast<lua_Number>(module_base()));
    (void)idx;
    lua_setglobal(L, "zeno_offsets");
}

struct Executor::Impl {
    lua_State* L = nullptr;
    std::thread worker;
    std::mutex m;
    std::condition_variable cv;
    std::deque<std::string> scripts;
    std::vector<Pending> scheduled;
    bool running = false;
};

Executor& Executor::instance() {
    static Executor inst;
    return inst;
}

bool Executor::init() {
    if (d) return true;
    d = new Impl{};

    d->L = luaL_newstate();
    if (!d->L) {
        bridge::out_err("luaL_newstate failed");
        delete d;
        d = nullptr;
        return false;
    }

    luaL_openlibs(d->L);
    install_api(d->L);

    size_t prelude_size = 0;
    char* prelude_bc = luau_compile(kPrelude, strlen(kPrelude), nullptr, &prelude_size);
    int prelude_status =
        prelude_bc ? luau_load(d->L, "=zeno_prelude", prelude_bc, prelude_size, 0) : LUA_ERRSYNTAX;
    free(prelude_bc);

    if (prelude_status != LUA_OK) {
        bridge::out_err(lua_tostring(d->L, -1));
        lua_pop(d->L, 1);
    } else if (lua_pcall(d->L, 0, 0, 0) != LUA_OK) {
        bridge::out_err(lua_tostring(d->L, -1));
        lua_pop(d->L, 1);
    }

    d->running = true;
    d->worker = std::thread([this] { worker(); });

    bridge::out("[zeno] luau runtime online");
    return true;
}

void Executor::shutdown() {
    if (!d) return;
    {
        std::lock_guard lock(d->m);
        d->running = false;
    }
    d->cv.notify_all();
    if (d->worker.joinable()) d->worker.join();
    if (d->L) lua_close(d->L);
    delete d;
    d = nullptr;
}

void Executor::execute(std::string_view source) {
    if (!d) return;
    {
        std::lock_guard lock(d->m);
        d->scripts.emplace_back(source);
    }
    d->cv.notify_one();
}

void Executor::worker() {
    while (true) {
        std::deque<std::string> batch;
        std::vector<std::pair<int, int>> due;

        {
            std::unique_lock lock(d->m);
            d->cv.wait_for(lock, std::chrono::milliseconds(4), [this] {
                return !d->running || !d->scripts.empty();
            });
            if (!d->running) return;
            batch.swap(d->scripts);

            const long long t = now_ms();
            for (auto it = d->scheduled.begin(); it != d->scheduled.end();) {
                if (it->due <= t) {
                    due.emplace_back(it->ref, it->nargs);
                    it = d->scheduled.erase(it);
                } else {
                    ++it;
                }
            }        }

        for (auto& script : batch) run_script(script);

        for (auto& [ref, nargs] : due) resume(ref, nargs);
    }
}

void Executor::run_script(const std::string& source) {
    size_t bc_size = 0;
    char* bc = luau_compile(source.data(), source.size(), nullptr, &bc_size);
    if (!bc) {
        bridge::out_err("compile failed: out of memory");
        return;
    }

    lua_State* co = lua_newthread(d->L);
    int ref = lua_ref(d->L, -1);

    int status = luau_load(co, "=zeno", bc, bc_size, 0);
    free(bc);

    if (status != LUA_OK) {
        const char* err = lua_tostring(co, -1);
        bridge::out_err(err ? err : "compile error");
        lua_settop(co, 0);
        lua_unref(d->L, ref);
        return;
    }

    settle(lua_resume(co, d->L, 0), co, ref, "=zeno");
}

void Executor::schedule(int thread_ref, long long delay_ms, int nargs) {
    std::lock_guard lock(d->m);
    d->scheduled.push_back({thread_ref, now_ms() + delay_ms, nargs});
}

int Executor::spawn_from(lua_State* caller, long long delay_ms) {
    if (!d) return -1;
    const int nvals = lua_gettop(caller);
    if (nvals < 1 || !lua_isfunction(caller, 1)) return -1;

    lua_State* co = lua_newthread(caller);       // pushes the thread
    const int ref = lua_ref(caller, -1); // pops it
    lua_xmove(caller, co, nvals);                // fn + args land on co

    schedule(ref, delay_ms, nvals - 1);
    return ref;
}

void Executor::resume(int thread_ref, int nargs) {
    lua_rawgeti(d->L, LUA_REGISTRYINDEX, thread_ref);
    lua_State* co = lua_tothread(d->L, -1);
    lua_pop(d->L, 1);
    if (!co) return;

    settle(lua_resume(co, d->L, nargs), co, thread_ref, "=zeno");
}

void Executor::settle(int status, lua_State* co, int ref, const char* chunk) {
    if (status == LUA_YIELD) {
        long long wait_ms = 0;
        if (lua_gettop(co) >= 1 && lua_isnumber(co, -1)) {
            wait_ms = static_cast<long long>(lua_tonumber(co, -1) * 1000.0);
        }
        lua_settop(co, 0);
        schedule(ref, std::max<long long>(0, wait_ms), 0);
        return;
    }

    if (status != LUA_OK) {
        const char* err = lua_tostring(co, -1);
        if (err && *err) {
            bridge::out_err(err);
        } else {
            bridge::out_err("script raised a non-string error");
        }
    }

    lua_settop(co, 0);
    lua_unref(d->L, ref);
    (void)chunk;
}

} // namespace zeno
