#include <windows.h>

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
    zeno::bridge::start([](std::string_view script) {
        zeno::Executor::instance().execute(script);
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
