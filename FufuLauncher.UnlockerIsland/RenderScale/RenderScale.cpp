#include "RenderScale.h"
#include "../Config/Config.h"
#include "../MinHook/MinHook.h"
#include "../Patterns/Patterns.h"
#include "../Scanner/Scanner.h"
#include <iostream>

namespace RenderScaleFeature {
    void* g_oBuildCmdBuffers = nullptr;

    typedef void(__fastcall* tBuildCmdBuffers)(void*);

    void __fastcall HookBuildCmdBuffers(void* pThis) {
        if (Config::Get().enable_render_scale) {
            *(float*)((uintptr_t)pThis + 0x84) = Config::Get().render_scale_value;
        }
        
        if (g_oBuildCmdBuffers) {
            ((tBuildCmdBuffers)g_oBuildCmdBuffers)(pThis);
        }
    }

    void Init() {
        std::cout << "[SCAN] Hooking BuildCmdBuffers (Render Scale)..." << std::endl;
        void* addr = Scanner::ScanMainMod(Patterns::BuildCmdBuffers);
        if (addr) {
            if (MH_CreateHook(addr, (void*)HookBuildCmdBuffers, &g_oBuildCmdBuffers) == MH_OK) {
                std::cout << "   -> BuildCmdBuffers Hook Ready." << std::endl;
            } else {
                std::cout << "   -> [ERR] BuildCmdBuffers Hook Failed." << std::endl;
            }
        } else {
            std::cout << "   -> [ERR] BuildCmdBuffers Pattern Not Found." << std::endl;
        }
    }
}