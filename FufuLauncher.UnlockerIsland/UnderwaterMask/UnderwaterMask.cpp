#include "UnderwaterMask.h"
#include "../Config/Config.h"
#include "../Scanner/Scanner.h"
#include "../Patterns/Patterns.h"
#include "../MinHook/MinHook.h"
#include <cstdint>
#include <iostream>

namespace UnderwaterMask {

    typedef void(__fastcall* fn_LELJFPLMCFH)(void* thisPtr, void* unused);
    typedef void(__fastcall* fn_GLPLONFPPDM)(void* thisPtr, void* unused);

    static fn_LELJFPLMCFH g_origLELJFPLMCFH = nullptr;
    static fn_GLPLONFPPDM g_fnGLPLONFPDM = nullptr;

    static void __fastcall Hooked_LELJFPLMCFH(void* thisPtr, void* unused) {
        if (g_fnGLPLONFPDM) {
            g_fnGLPLONFPDM(thisPtr, nullptr);
        }
    }

    static uintptr_t FindPatternLocal(uintptr_t base, size_t size, const uint8_t* pattern, const char* mask) {
        size_t patternLen = strlen(mask);
        for (size_t i = 0; i <= size - patternLen; ++i) {
            bool found = true;
            for (size_t j = 0; j < patternLen; ++j) {
                if (mask[j] == 'x' && ((uint8_t*)base)[i + j] != pattern[j]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return base + i;
            }
        }
        return 0;
    }

    void Init() {
        if (!Config::Get().disable_underwater_mask) return;

        void* addrMain = Scanner::ScanMainMod(Patterns::UnderwaterMaskMain);
        if (addrMain) {
            uintptr_t mainPtr = (uintptr_t)addrMain;
            
            const uint8_t sigClear[] = { 0x56, 0x57, 0x48, 0x83, 0xEC, 0x28, 0x48, 0x89, 0xCE, 0x80, 0x3D };
            const char maskClear[] = "xxxxxxxxxxx";
            
            uintptr_t searchStart = (mainPtr >= 0x800) ? (mainPtr - 0x800) : 0;
            uintptr_t addrClear = FindPatternLocal(searchStart, 0x800, sigClear, maskClear);
            
            if (addrClear) {
                g_fnGLPLONFPDM = (fn_GLPLONFPPDM)addrClear;
                std::cout << "[SCAN] Underwater Mask Clear Function Found.\n";
            } else {
                std::cout << "[WARN] Underwater Mask Clear Function Not Found, skipping active cleanup.\n";
            }

            if (MH_CreateHook(addrMain, (void*)Hooked_LELJFPLMCFH, (void**)&g_origLELJFPLMCFH) == MH_OK) {
                std::cout << "[SCAN] Underwater Mask Hook Ready.\n";
            } else {
                std::cout << "[ERR] Underwater Mask Hook Failed.\n";
            }
        } else {
            std::cout << "[ERR] Underwater Mask Pattern Not Found.\n";
        }
    }
}