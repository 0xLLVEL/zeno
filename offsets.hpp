//=================
// Credoxy 2.6.9
// version-f0ea5da9412f4e35
// dumped 62/62
// dump time: 37.666s
//=================

#pragma once
#include <cstdint>
#include <windows.h>

#define REBASE(x) ((uintptr_t)GetModuleHandle(0) + (x))

namespace Offsets
{
    const uintptr_t Print = REBASE(0x1CA9A30);
    const uintptr_t OpcodeLookupTable = REBASE(0x735B280);
    const uintptr_t ScriptContextResume = REBASE(0x431B1F0);
    const uintptr_t GetLuaStateForInstance = REBASE(0x4274C30);
    const uintptr_t LuaVMLoad = REBASE(0x426A570);
    const uintptr_t luaD_throw = REBASE(0x26360E0);
    const uintptr_t TaskDefer = REBASE(0x435C440);

    namespace reflections
    {
        const uintptr_t CastArgs = REBASE(0x41CB820);
    }

    namespace Signals
    {
        const uintptr_t FireTouchInterest = REBASE(0x14B6AE0);
        const uintptr_t DisconnectConnect = REBASE(0x4239210);
    }

    namespace signal_offsets
    {
        constexpr uintptr_t signature = 0x60;
        namespace connection
        {
            constexpr uintptr_t next = 0x10;
            constexpr uintptr_t enabled = 0x20;
            constexpr uintptr_t slot_wrapper = 0x30;
            constexpr uintptr_t slot_wrapper_self = 0x38;
        }
        namespace slot_wrapper
        {
            constexpr uintptr_t thread = 0x28;
            constexpr uintptr_t function_id = 0x30;
            constexpr uintptr_t function_id_fallback = 0x34;
            constexpr uintptr_t weak_object_ref = 0xA0;
            constexpr uintptr_t weak_object_ref_fallback = 0x90;
        }
    }

    namespace Flags
    {
        const uintptr_t FireLeftMouseClick = REBASE(0x3C6DAF0);
        const uintptr_t FireRightMouseClick = REBASE(0x3C6DC90);
        const uintptr_t FireMouseHoverEnter = REBASE(0x3C6F060);
        const uintptr_t FireMouseHoverLeave = REBASE(0x3C6F200);
        const uintptr_t FireProximityPrompt = REBASE(0x30FD840);
    }

    namespace Luau
    {
        const uintptr_t Luau_Execute = REBASE(0x26789E0);
        const uintptr_t LuaO_NilObject = REBASE(0x68BA8E8);
        const uintptr_t LuaH_DummyNode = REBASE(0x68B9F58);
    }

    namespace Extras
    {
        const uintptr_t k_table = REBASE(0x8530CF0);
    }

    namespace ExtraSpace
    {
        const uintptr_t RequireBypass = 0xB71;
        const uintptr_t ScriptContextToResume = 0xA28;
    }

    namespace InstanceBridge
    {
        const uintptr_t Push = REBASE(0x42594C0);
    }

    namespace ClassDescriptor
    {
        const uintptr_t GetPropertyData = REBASE(0x1CEBC50);
        const uintptr_t GetProperty = REBASE(0x1CE8360);
    }

    namespace RobloxThread
    {
        const uintptr_t IdentityPtr = REBASE(0x855CF68);
        const uintptr_t GetTlsPointer = REBASE(0xC700);
    }

    namespace Capabilities
    {
        const uintptr_t GetCapabilities = REBASE(0x1CEA140);
        const uintptr_t Capabilities = 0x30;
    }

    namespace Bytecode
    {
        const uintptr_t Pointer = 0x10;
        const uintptr_t Size = 0x20;
        const uintptr_t LocalScriptByteCode = 0x178;
        const uintptr_t ModuleScriptByteCode = 0x120;
    }

    namespace DataModel
    {
        const uintptr_t FakeDM = REBASE(0x8EB6960);
        const uintptr_t DataModel = 0x1F0;
        const uintptr_t PlaceId = 0x180;
        const uintptr_t Children = 0x70;
        const uintptr_t GameId = 0x178;
        const uintptr_t JobId = 0x108;
        const uintptr_t ScriptContext = 0x440;
        const uintptr_t GameLoaded = 0x588;
    }

    namespace Scheduler
    {
        const uintptr_t TaskScheduler = REBASE(0x8E4D7B8);
        const uintptr_t JobStart = 0xC8;
        const uintptr_t JobEnd = 0xD0;
        const uintptr_t JobTypeName = 0x18;
        const uintptr_t Fps = 0xB0;
    }

    namespace FFlags
    {
        const uintptr_t GetFFlag = REBASE(0x4B12B50);
        const uintptr_t SetFFlag = REBASE(0x4B12050);
        const uintptr_t FFlagPointer = REBASE(0x858F8E8);
        const uintptr_t BooleanType = REBASE(0x71DE5A8);
        const uintptr_t BooleanValueType = REBASE(0x71DE7D8);
        const uintptr_t IntegerType = REBASE(0x71DE6C0);
        const uintptr_t IntegerValueType = REBASE(0x71DE8F0);
    }
}
