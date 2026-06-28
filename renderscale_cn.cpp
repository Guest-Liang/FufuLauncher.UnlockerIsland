#include "../../MinHook/MinHook.h"
#include <windows.h>
#include <psapi.h>
#include <cstdint>

namespace Config {
    constexpr float RenderScale = 0.01f;
    constexpr uintptr_t ScaleOffset = 0x84;
}

static const char* SIG = "41 57 41 56 41 55 41 54 56 57 55 53 48 81 EC 48 02 00 00 48 89 CE 0F 57 C0 0F 29 84 24 50 01 00 00 0F 29 84 24 40 01 00 00 0F 29 84 24 30 01 00";

typedef void (__fastcall *FnBuildCmdBuffers)(void*);
static FnBuildCmdBuffers fpOriginal = nullptr;

static uintptr_t PatternScan(uintptr_t base) {
    uint8_t sig[128];
    size_t len = 0;
    const char* p = SIG;
    while (*p && len < 128) {
        while (*p == ' ') p++;
        if (!*p) break;
        char hex[3] = { p[0], p[1], 0 };
        sig[len] = (uint8_t)strtoul(hex, nullptr, 16);
        len++;
        p += 2;
    }

    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = base;
    while (VirtualQuery((void*)addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            uintptr_t end = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
            for (uintptr_t i = (uintptr_t)mbi.BaseAddress; i < end - len; i++) {
                bool ok = true;
                for (size_t j = 0; j < len; j++) {
                    if (*(uint8_t*)(i + j) != sig[j]) { ok = false; break; }
                }
                if (ok) return i;
            }
        }
        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }
    return 0;
}

static void __fastcall HkBuildCmdBuffers(void* pThis) {
    *(float*)((uintptr_t)pThis + Config::ScaleOffset) = Config::RenderScale;
    fpOriginal(pThis);
}

static DWORD WINAPI MainThread(LPVOID) {
    while (!FindWindowA("UnityWndClass", nullptr))
        Sleep(100);
    Sleep(8000);

    uintptr_t base = (uintptr_t)GetModuleHandleA(NULL);
    if (!base) return 0;

    uintptr_t target = PatternScan(base);
    if (!target) return 0;

    MH_Initialize();
    if (MH_CreateHook((void*)target, (void*)HkBuildCmdBuffers, (void**)&fpOriginal) != MH_OK)
        return 0;
    MH_EnableHook((void*)target);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, MainThread, nullptr, 0, nullptr);
    }
    else if (reason == DLL_PROCESS_DETACH) {
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
    }
    return TRUE;
}
