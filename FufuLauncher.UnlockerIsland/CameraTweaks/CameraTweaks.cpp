#include "CameraTweaks.h"
#include "../Config/Config.h"
#include "../Scanner/Scanner.h"
#include "../Patterns/Patterns.h"
#include "../MinHook/MinHook.h"
#include <cstdint>
#include <iostream>

namespace CameraTweaks {

    using fn_GetDeltaTime = float(__fastcall*)();
    static fn_GetDeltaTime pGetDeltaTime = nullptr;

    using fn_UpdateView = void(__fastcall*)(void* thisPtr);
    static fn_UpdateView oUpdateView = nullptr;

    using fn_Tick = void(__fastcall*)(void* thisPtr, float deltaTime);
    static fn_Tick oTick = nullptr;

    static void __fastcall hkUpdateView(void* thisPtr) {
        float* self = (float*)thisPtr;

        float dt = pGetDeltaTime ? pGetDeltaTime() : (1.0f / 60.0f);
        float inputX = self[28];
        float inputY = self[29];
        float speed  = self[33];

        self[11] += dt * inputX * speed;

        float newPitch = self[10] + dt * inputY * speed;
        if (newPitch < -15.0f) newPitch = -15.0f;
        if (newPitch > 70.0f)  newPitch = 70.0f;
        self[10] = newPitch;

        self[30] = inputX;
        self[31] = inputY;
    }

    static void __fastcall hkTick(void* thisPtr, float deltaTime) {
        uint8_t* self = (uint8_t*)thisPtr;
        float duration = *(float*)(self + 0x64);
        *(float*)(self + 0x5C) = duration;
        if (oTick) {
            oTick(thisPtr, deltaTime);
        }
    }

    void Init() {
        ModConfig& cfg = Config::Get();

        if (cfg.disable_camera_smooth) {
            void* addrUpdateView = Scanner::ScanMainMod(Patterns::CameraUpdateView);
            if (addrUpdateView) {
                uint8_t* callSite = (uint8_t*)addrUpdateView + 0x28;
                if (*callSite == 0xE8) {
                    int32_t rel = *(int32_t*)(callSite + 1);
                    pGetDeltaTime = (fn_GetDeltaTime)(callSite + 5 + rel);
                }
                
                if (MH_CreateHook(addrUpdateView, (void*)hkUpdateView, (void**)&oUpdateView) == MH_OK) {
                    std::cout << "[SCAN] Camera UpdateView Hook Ready.\n";
                } else {
                    std::cout << "[ERR] Camera UpdateView Hook Failed.\n";
                }
            } else {
                std::cout << "[ERR] Camera UpdateView Pattern Not Found.\n";
            }
        }

        if (cfg.disable_camera_blend) {
            void* addrTick = Scanner::ScanMainMod(Patterns::CameraStateBlenderTick);
            if (addrTick) {
                if (MH_CreateHook(addrTick, (void*)hkTick, (void**)&oTick) == MH_OK) {
                    std::cout << "[SCAN] CameraStateBlender Tick Hook Ready.\n";
                } else {
                    std::cout << "[ERR] CameraStateBlender Tick Hook Failed.\n";
                }
            } else {
                std::cout << "[ERR] CameraStateBlender Tick Pattern Not Found.\n";
            }
        }
    }
}