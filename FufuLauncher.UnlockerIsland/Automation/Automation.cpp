#include "Automation.h"
#include <iostream>
#include <cstring>

namespace HelperAddr {
    uintptr_t InnerDispatcher   = 0;
    uintptr_t CookHandler       = 0;
    uintptr_t CookShowPage      = 0;
    uintptr_t CookPatchAfterInit = 0;
    uintptr_t CookPatchEntity   = 0;
    uintptr_t CookPatchPathB    = 0;
    uintptr_t CookPatchBplSkip  = 0;
    uintptr_t CookPatchNullChk1 = 0;
    uintptr_t CookPatchNullChk2 = 0;
    uintptr_t CookPatchNullTgt1 = 0;
    uintptr_t CookPatchNullTgt2 = 0;
    uintptr_t CookPatchFireWr   = 0;
    uintptr_t ExpHandler        = 0;
}

const BYTE CookingHash[4]    = { 0x1C, 0xCE, 0x1B, 0x4C };
const BYTE ExpeditionHash[4] = { 0xE1, 0x73, 0x90, 0x69 };
Fn_CookShowPage g_oCookShowPage = nullptr;

static uint32_t g_CookFireState = 0;
static uint32_t g_CookFireParam = 0;
static uint32_t g_CookEntityRef = 0;
bool g_CookReady = false;
BYTE g_CookHandlerPrologue[8] = {0};
static BYTE g_CookSnapAfterInit[7] = {0};
static BYTE g_CookSnapEntity[9]  = {0};
static BYTE g_CookSnapBplSkip[1] = {0};
static BYTE g_CookSnapNullChk1[6] = {0};
static BYTE g_CookSnapNullChk2[6] = {0};
static volatile bool g_CookHookActive = false;
static volatile LONG g_CookPatchLock  = 0;

BYTE g_ExpHandlerPrologue[8] = {0};
volatile bool g_TrigCook  = false;
volatile bool g_TrigExp   = false;
DWORD g_LastCookTime  = 0;
DWORD g_LastExpTime   = 0;

uintptr_t FindHandlerByHash(uintptr_t dispBase, const BYTE hash[4]) {
    for (uintptr_t s = dispBase; s < dispBase + 0x20000 - 4; ++s) {
        __try {
            if (memcmp((void*)s, hash, 4) != 0) continue;

            uintptr_t cmpStart  = 0;
            uintptr_t afterCmp  = 0;
            if (*(BYTE*)(s - 2) == 0x81 && *(BYTE*)(s - 1) == 0xF9) {
                cmpStart = s - 2;
                afterCmp = s + 4;
            } else if (*(BYTE*)(s - 1) == 0x3D) {
                cmpStart = s - 1;
                afterCmp = s + 4;
            } else continue;

            BYTE b0 = *(BYTE*)afterCmp;
            BYTE b1 = *(BYTE*)(afterCmp + 1);
            bool isEq = (b0 == 0x74) || (b0 == 0x75) || (b0 == 0x0F && (b1 == 0x84 || b1 == 0x85));

            if (isEq) {
                for (uintptr_t t = cmpStart; t < cmpStart + 0x200; t++) {
                    if (*(BYTE*)t == 0x41 && *(BYTE*)(t + 1) == 0x5F && *(BYTE*)(t + 2) == 0xE9) {
                        int32_t rel = *(int32_t*)(t + 3);
                        return (t + 2) + 5 + rel;
                    }
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) { break; }
    }
    return 0;
}

uintptr_t FindExpeditionHandler(uintptr_t dispBase, const BYTE hash[4]) {
    uintptr_t leafJe = 0, firstCmp = 0;
    for (uintptr_t s = dispBase; s < dispBase + 0x20000 - 4; s++) {
        __try {
            if (memcmp((void*)s, hash, 4) != 0) continue;
            uintptr_t cmp = 0;
            if (*(BYTE*)(s - 2) == 0x81 && *(BYTE*)(s - 1) == 0xF9) cmp = s - 2;
            else if (*(BYTE*)(s - 1) == 0x3D) cmp = s - 1;
            if (!cmp) continue;
            if (!firstCmp) firstCmp = cmp;
            uintptr_t ac = (*(BYTE*)cmp == 0x81) ? cmp + 6 : cmp + 5;
            for (uintptr_t t = ac; t < ac + 10; t++) {
                if (*(BYTE*)t == 0x0F && *(BYTE*)(t+1) == 0x84) { leafJe = t + 6 + *(int32_t*)(t + 2); break; }
                if (*(BYTE*)t == 0x0F && *(BYTE*)(t+1) == 0x85) { leafJe = t + 6; break; }
                if (*(BYTE*)t == 0x74) { leafJe = t + 2 + *(int8_t*)(t + 1); break; }
                if (*(BYTE*)t == 0x75) { leafJe = t + 2; break; }
            }
            if (leafJe) break;
        } __except(EXCEPTION_EXECUTE_HANDLER) { break; }
    }
    uintptr_t start = leafJe ? leafJe : firstCmp;
    if (!start) return 0;
    uintptr_t handler = 0;
    for (uintptr_t s = start; s < start + 0x200; s++) {
        __try {
            if (*(BYTE*)s == 0x41 && *(BYTE*)(s+1) == 0x5F && *(BYTE*)(s+2) == 0xE9) {
                int32_t rel = *(int32_t*)(s + 3);
                handler = (s + 2) + 5 + rel;
                break;
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) { break; }
    }
    return handler;
}

bool ResolveCookingPatches() {
    if (!HelperAddr::CookHandler) return false;
    memcpy(g_CookHandlerPrologue, (void*)HelperAddr::CookHandler, 8);
    uintptr_t h = HelperAddr::CookHandler;
    uintptr_t hEnd = h + 0x600;
    bool ok = true;
    __try {
        for (uintptr_t s = h + 0x200; s < hEnd - 30; s++) {
            if (*(BYTE*)s == 0x48 && *(BYTE*)(s+1) == 0x8B && *(BYTE*)(s+2) == 0x0D &&
                *(BYTE*)(s+7) == 0xE8 &&
                *(BYTE*)(s+12) == 0x48 && *(BYTE*)(s+13) == 0x89 && *(BYTE*)(s+14) == 0xC3 &&
                *(BYTE*)(s+15) == 0x48 && *(BYTE*)(s+16) == 0x8B && *(BYTE*)(s+17) == 0x0D &&
                *(BYTE*)(s+22) == 0xE8 &&
                *(BYTE*)(s+27) == 0x48 && *(BYTE*)(s+28) == 0x89 && *(BYTE*)(s+29) == 0xC6) {
                HelperAddr::CookPatchPathB = s; break;
            }
        }
        if (!HelperAddr::CookPatchPathB) ok = false;
        if (HelperAddr::CookPatchPathB) {
            uintptr_t s = h + 0x31;
            if (*(BYTE*)s == 0x48 && *(BYTE*)(s + 1) == 0x8B && *(BYTE*)(s + 2) == 0x90 &&
                *(BYTE*)(s + 5) == 0x00 && *(BYTE*)(s + 6) == 0x00 &&
                *(BYTE*)(s + 7) == 0x48 && *(BYTE*)(s + 8) == 0x85 && *(BYTE*)(s + 9) == 0xD2) {
                HelperAddr::CookPatchAfterInit = s;
            }
        }
        if (!HelperAddr::CookPatchAfterInit) ok = false;
        if (HelperAddr::CookPatchPathB) {
            for (uintptr_t s = h + 0x100; s < HelperAddr::CookPatchPathB; s++) {
                if (*(BYTE*)s == 0x48 && *(BYTE*)(s+1) == 0x85 && *(BYTE*)(s+2) == 0xDB &&
                    *(BYTE*)(s+3) == 0x0F && *(BYTE*)(s+4) == 0x84) HelperAddr::CookPatchEntity = s;
            }
        }
        if (!HelperAddr::CookPatchEntity) ok = false;
        if (HelperAddr::CookPatchPathB) {
            for (uintptr_t s = HelperAddr::CookPatchPathB; s < hEnd - 19; s++) {
                bool hasWideEntityStore =
                    *(BYTE*)(s + 12) == 0x4C && *(BYTE*)(s + 13) == 0x89 &&
                    *(BYTE*)(s + 14) == 0xB6 && *(BYTE*)(s + 18) == 0x00;
                bool hasShortEntityStore =
                    *(BYTE*)(s + 12) == 0x4C && *(BYTE*)(s + 13) == 0x89 &&
                    *(BYTE*)(s + 14) == 0x76;

                if (*(BYTE*)s        == 0x89 && *(BYTE*)(s + 1)  == 0x86 &&
                    *(BYTE*)(s + 4)  == 0x00 && *(BYTE*)(s + 5)  == 0x00 &&
                    *(BYTE*)(s + 6)  == 0x89 && *(BYTE*)(s + 7)  == 0x8E &&
                    *(BYTE*)(s + 10) == 0x00 && *(BYTE*)(s + 11) == 0x00 &&
                    (hasWideEntityStore || hasShortEntityStore)) {
                    HelperAddr::CookPatchFireWr = s;
                    g_CookFireState = *(uint16_t*)(s + 2);
                    g_CookFireParam = *(uint16_t*)(s + 8);
                    g_CookEntityRef = hasShortEntityStore ? *(BYTE*)(s + 15) : *(uint16_t*)(s + 15);
                    break;
                }
            }
        }
        if (!HelperAddr::CookPatchFireWr) ok = false;
        if (HelperAddr::CookPatchFireWr) {
            for (uintptr_t s = HelperAddr::CookPatchFireWr - 1; s > HelperAddr::CookPatchFireWr - 0x20 && s > h; s--) {
                if (*(BYTE*)s == 0x40 && *(BYTE*)(s+1) == 0x84 && *(BYTE*)(s+2) == 0xED &&
                    *(BYTE*)(s+3) == 0x75) { HelperAddr::CookPatchBplSkip = s + 3; break; }
            }
        }
        if (!HelperAddr::CookPatchBplSkip) ok = false;
        if (HelperAddr::CookPatchPathB && HelperAddr::CookPatchFireWr) {
            int cnt = 0;
            for (uintptr_t s = HelperAddr::CookPatchPathB; s < HelperAddr::CookPatchFireWr; s++) {
                if (*(BYTE*)s == 0x48 && *(BYTE*)(s+1) == 0x85 && *(BYTE*)(s+2) == 0xC0 &&
                    *(BYTE*)(s+3) == 0x0F && *(BYTE*)(s+4) == 0x84) {
                    cnt++;
                    if (cnt == 1) {
                        HelperAddr::CookPatchNullChk1 = s + 3;
                        for (uintptr_t t = s + 9; t < HelperAddr::CookPatchFireWr; t++) {
                            bool hasWideLoad =
                                *(BYTE*)t       == 0x48 && *(BYTE*)(t + 1) == 0x8B && *(BYTE*)(t + 2) == 0x86 &&
                                *(BYTE*)(t + 5) == 0x00 && *(BYTE*)(t + 6) == 0x00;
                            bool hasShortLoad =
                                *(BYTE*)t == 0x48 && *(BYTE*)(t + 1) == 0x8B && *(BYTE*)(t + 2) == 0x46;

                            if (hasWideLoad || hasShortLoad) {
                                HelperAddr::CookPatchNullTgt1 = t; break;
                            }
                        }
                    } else if (cnt == 2) {
                        HelperAddr::CookPatchNullChk2 = s + 3;
                        for (uintptr_t t = s + 9; t < HelperAddr::CookPatchFireWr; t++) {
                            if (*(BYTE*)t == 0x48 && *(BYTE*)(t+1) == 0x85 && *(BYTE*)(t+2) == 0xDB) {
                                HelperAddr::CookPatchNullTgt2 = t; break;
                            }
                        }
                        break;
                    }
                }
            }
            if (cnt < 2) ok = false;
        }
        if (!HelperAddr::CookPatchNullTgt1 || !HelperAddr::CookPatchNullTgt2) ok = false;
        for (uintptr_t s = h + 0x300; s < h + 0x600; s++) {
            if (*(BYTE*)s == 0xE8 && *(BYTE*)(s+5) == 0x40 && *(BYTE*)(s+6) == 0xB6 && *(BYTE*)(s+7) == 0x01) {
                int32_t rel = *(int32_t*)(s + 1);
                HelperAddr::CookShowPage = s + 5 + rel;
                break;
            }
        }
        if (ok) {
            memcpy(g_CookSnapAfterInit, (void*)HelperAddr::CookPatchAfterInit, 7);
            memcpy(g_CookSnapEntity,  (void*)HelperAddr::CookPatchEntity,   9);
            memcpy(g_CookSnapBplSkip, (void*)HelperAddr::CookPatchBplSkip,  1);
            memcpy(g_CookSnapNullChk1,(void*)HelperAddr::CookPatchNullChk1, 6);
            memcpy(g_CookSnapNullChk2,(void*)HelperAddr::CookPatchNullChk2, 6);
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) { ok = false; }
    return ok;
}

__int64 __fastcall hk_CookShowPage(__int64 a1, __int64 a2) {
    if (g_CookHookActive && a1) {
        g_CookHookActive = false;
        __try {
            uintptr_t v35 = *(uintptr_t*)(a1 + HelperField::CookCtxV35);
            if (v35) {
                uintptr_t v2 = *(uintptr_t*)(v35 + HelperField::CookCtxV2);
                if (v2) {
                    uint32_t oFS = g_CookFireState ? g_CookFireState : HelperField::CookFireStateDef;
                    uint32_t oFP = g_CookFireParam ? g_CookFireParam : HelperField::CookFireParamDef;
                    uint32_t oER = g_CookEntityRef ? g_CookEntityRef : HelperField::CookEntityRefDef;
                    *(uint32_t*)(v2 + oFS) = HelperField::CookHookMagic1;
                    *(uint32_t*)(v2 + oFP) = HelperField::CookHookMagic1;
                    *(uintptr_t*)(v2 + oER) = 0;
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
    }
    return g_oCookShowPage(a1, a2);
}

void DoCookingLogic() {
    std::cout << "[Cook] Attempting to execute auto cook." << std::endl;

    if (!HelperAddr::CookHandler) {
        std::cout << "[Cook] Failed: CookHandler address is null (scan missed)." << std::endl;
        return;
    }
    if (!g_CookReady) {
        std::cout << "[Cook] Failed: g_CookReady is false (patch resolution failed)." << std::endl;
        return;
    }
    if (InterlockedCompareExchange(&g_CookPatchLock, 1, 0) != 0) {
        std::cout << "[Cook] Failed: Currently executing (lock conflict)." << std::endl;
        return;
    }

    if (memcmp((void*)HelperAddr::CookHandler, g_CookHandlerPrologue, 8) != 0 ||
        memcmp((void*)HelperAddr::CookPatchAfterInit, g_CookSnapAfterInit, 7) != 0 ||
        memcmp((void*)HelperAddr::CookPatchEntity,   g_CookSnapEntity,   9) != 0 ||
        memcmp((void*)HelperAddr::CookPatchBplSkip,  g_CookSnapBplSkip,  1) != 0 ||
        memcmp((void*)HelperAddr::CookPatchNullChk1, g_CookSnapNullChk1, 6) != 0 ||
        memcmp((void*)HelperAddr::CookPatchNullChk2, g_CookSnapNullChk2, 6) != 0) {
        g_CookReady = false;
        InterlockedExchange(&g_CookPatchLock, 0);
        std::cout << "[Cook] Failed: Memory signature mismatch. Memory has been modified." << std::endl;
        return;
    }

    std::cout << "[Cook] Memory check passed. Applying patches." << std::endl;

    BYTE oAI[7], oEV[9], oBP[1], oN1[6], oN2[6];
    memcpy(oAI, (void*)HelperAddr::CookPatchAfterInit, 7);
    memcpy(oEV, (void*)HelperAddr::CookPatchEntity,   9);
    memcpy(oBP, (void*)HelperAddr::CookPatchBplSkip,  1);
    memcpy(oN1, (void*)HelperAddr::CookPatchNullChk1, 6);
    memcpy(oN2, (void*)HelperAddr::CookPatchNullChk2, 6);

    uintptr_t lo = HelperAddr::CookPatchAfterInit;
    uintptr_t hi = HelperAddr::CookPatchFireWr + 19;
    DWORD oldProt;
    VirtualProtect((void*)lo, (SIZE_T)(hi - lo), PAGE_EXECUTE_READWRITE, &oldProt);

    {
        int32_t disp = (int32_t)(HelperAddr::CookPatchPathB - (HelperAddr::CookPatchAfterInit + 5));
        BYTE patch[7] = { 0xE9, 0, 0, 0, 0, 0x90, 0x90 };
        memcpy(patch + 1, &disp, 4);
        memcpy((void*)HelperAddr::CookPatchAfterInit, patch, 7);
    }
    {
        int32_t disp = (int32_t)(HelperAddr::CookPatchPathB - (HelperAddr::CookPatchEntity + 5));
        BYTE patch[9] = { 0xE9, 0, 0, 0, 0, 0x90, 0x90, 0x90, 0x90 };
        memcpy(patch + 1, &disp, 4);
        memcpy((void*)HelperAddr::CookPatchEntity, patch, 9);
    }
    *(BYTE*)HelperAddr::CookPatchBplSkip = 0xEB;
    {
        int32_t disp = (int32_t)(HelperAddr::CookPatchNullTgt2 - (HelperAddr::CookPatchNullChk2 + 6));
        BYTE patch[6] = { 0x0F, 0x84, 0, 0, 0, 0 };
        memcpy(patch + 2, &disp, 4);
        memcpy((void*)HelperAddr::CookPatchNullChk2, patch, 6);
    }
    {
        int32_t disp = (int32_t)(HelperAddr::CookPatchNullTgt1 - (HelperAddr::CookPatchNullChk1 + 6));
        BYTE patch[6] = { 0x0F, 0x84, 0, 0, 0, 0 };
        memcpy(patch + 2, &disp, 4);
        memcpy((void*)HelperAddr::CookPatchNullChk1, patch, 6);
    }

    VirtualProtect((void*)lo, (SIZE_T)(hi - lo), oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), (void*)lo, (SIZE_T)(hi - lo));

    std::cout << "[Cook] Patches applied. Calling handler." << std::endl;

    auto handler = (Fn_CookHandler)HelperAddr::CookHandler;
    static BYTE dummyCtx[4096] = {0};
    static BYTE dummyData[4096] = {0};
    g_CookHookActive = true;

    __try {
        handler((__int64)dummyCtx, (__int64)dummyData, 0);
        std::cout << "[Cook] Handler executed successfully." << std::endl;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        std::cout << "[Cook] Fatal: Exception occurred inside handler. Execution intercepted." << std::endl;
    }

    g_CookHookActive = false;

    std::cout << "[Cook] Restoring memory." << std::endl;
    VirtualProtect((void*)lo, (SIZE_T)(hi - lo), PAGE_EXECUTE_READWRITE, &oldProt);
    memcpy((void*)HelperAddr::CookPatchAfterInit, oAI, 7);
    memcpy((void*)HelperAddr::CookPatchEntity,   oEV, 9);
    memcpy((void*)HelperAddr::CookPatchBplSkip,  oBP, 1);
    memcpy((void*)HelperAddr::CookPatchNullChk1, oN1, 6);
    memcpy((void*)HelperAddr::CookPatchNullChk2, oN2, 6);
    VirtualProtect((void*)lo, (SIZE_T)(hi - lo), oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), (void*)lo, (SIZE_T)(hi - lo));

    InterlockedExchange(&g_CookPatchLock, 0);
    std::cout << "[Cook] Auto cook sequence completed." << std::endl;
}

void DoExpeditionLogic() {
    std::cout << "[Expedition] Attempting to execute auto expedition." << std::endl;

    if (!HelperAddr::ExpHandler) {
        std::cout << "[Expedition] Failed: ExpHandler address is null (scan missed)." << std::endl;
        return;
    }

    __try {
        if (memcmp((void*)HelperAddr::ExpHandler, g_ExpHandlerPrologue, 8) != 0) {
            HelperAddr::ExpHandler = 0;
            std::cout << "[Expedition] Failed: ExpHandler memory signature changed. Pointer cleared." << std::endl;
            return;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        HelperAddr::ExpHandler = 0;
        std::cout << "[Expedition] Exception: Access violation reading ExpHandler memory." << std::endl;
        return;
    }

    std::cout << "[Expedition] Memory check passed. Calling handler." << std::endl;

    auto handler = (Fn_Handler)HelperAddr::ExpHandler;
    static BYTE dummyBuf[4096] = {0};

    __try {
        handler(0, (__int64)dummyBuf);
        std::cout << "[Expedition] Handler executed successfully (Path 1)." << std::endl;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        std::cout << "[Expedition] Path 1 exception. Attempting fallback path 2." << std::endl;
        __try {
            handler(0, 0);
            std::cout << "[Expedition] Handler executed successfully (Path 2)." << std::endl;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            HelperAddr::ExpHandler = 0;
            std::cout << "[Expedition] Fatal: Both paths crashed. Feature disabled." << std::endl;
        }
    }
}
