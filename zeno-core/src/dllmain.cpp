#include <windows.h>

#include <cstdint>
#include <string>
#include <string_view>

#include "bridge.h"
#include "executor.h"
#include "roblox.h"

namespace {

HMODULE g_self = nullptr;

DWORD WINAPI bootstrap(LPVOID) {
    // 1. Resolve the Roblox data model + offsets (never fatal).
    zeno::rbx::init();
    if (zeno::rbx::ready() && zeno::rbx::datamodel()) {
        zeno::bridge::out("[zeno] data model resolved");
    } else {
        zeno::bridge::out_warn("[zeno] data model unresolved — running in offline mode");
    }

    // 2. Bring up the Luau runtime before any script can arrive.
    if (!zeno::Executor::instance().init()) {
        zeno::bridge::out_err("[zeno] runtime init failed");
        return 1;
    }

    // 3. Attach the pipe bridge; every received frame runs on the worker.
    zeno::bridge::start([](std::string_view message) {
        // Control frames stay here; everything else is Lua.
        constexpr std::string_view kPrefix = "::zeno ";
        if (message.rfind(kPrefix, 0) == 0) {
            std::string_view command = message.substr(kPrefix.size());
            while (!command.empty() && (command.back() == '\n' || command.back() == '\r')) {
                command.remove_suffix(1);
            }
            if (command == "offsets") {
                zeno::bridge::out("[zeno] " + zeno::rbx::describe());
            } else if (command == "tree") {
                const uintptr_t dm = zeno::rbx::datamodel();
                if (dm == 0) {
                    zeno::bridge::out_warn("[zeno] no data model");
                } else {
                    std::string line = "[zeno] root=";
                    line += zeno::rbx::instance_name(dm);
                    line += " class=";
                    line += zeno::rbx::instance_class_name(dm);
                    line += " children=";
                    const auto children = zeno::rbx::instance_children(dm);
                    line += std::to_string(children.size());
                    zeno::bridge::out(line);

                    size_t shown = 0;
                    for (uintptr_t child : children) {
                        if (shown++ == 20) break;
                        std::string entry = "  ";
                        entry += zeno::rbx::instance_name(child);
                        entry += " [";
                        entry += zeno::rbx::instance_class_name(child);
                        entry += "]";
                        zeno::bridge::out(entry);
                    }
                }
            } else {
                zeno::bridge::out_warn("[zeno] unknown control command");
            }
            return;
        }
        zeno::Executor::instance().execute(message);
    });

    zeno::bridge::out("[zeno] ready — listening for scripts");
    return 0;
}

} // namespace

extern "C" __declspec(dllexport) void ZenoExecute(const char* source, int length) {
    if (!source || length <= 0) return;
    zeno::Executor::instance().execute(std::string_view(source, static_cast<size_t>(length)));
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    switch (reason) {
    case DLL_PROCESS_ATTACH: {
        g_self = module;
        DisableThreadLibraryCalls(module);
        HANDLE thread = CreateThread(nullptr, 0, bootstrap, nullptr, 0, nullptr);
        if (thread) CloseHandle(thread);
        break;
    }
    case DLL_PROCESS_DETACH:
        zeno::Executor::instance().shutdown();
        break;
    default:
        break;
    }
    return TRUE;
}
