#pragma once
#include <cstdint>

namespace RenderScaleFeature {
    extern void* g_oBuildCmdBuffers;
    void __fastcall HookBuildCmdBuffers(void* pThis);
    void Init();
}