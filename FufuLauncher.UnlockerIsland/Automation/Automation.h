#pragma once
#include "../Core/SharedState.h"
#include <cstdint>

namespace HelperField {
    constexpr uint32_t CookCtxV35         = 0x20;
    constexpr uint32_t CookCtxV2          = 0x10;
    constexpr uint32_t CookFireStateDef   = 0x248;
    constexpr uint32_t CookFireParamDef   = 0x250;
    constexpr uint32_t CookEntityRefDef   = 0xA0;
    constexpr uint32_t CookHookMagic1     = 0x3F800000;
}

namespace HelperAddr {
    extern uintptr_t InnerDispatcher;
    extern uintptr_t CookHandler;
    extern uintptr_t CookShowPage;
    extern uintptr_t CookPatchAfterInit;
    extern uintptr_t CookPatchEntity;
    extern uintptr_t CookPatchPathB;
    extern uintptr_t CookPatchBplSkip;
    extern uintptr_t CookPatchNullChk1;
    extern uintptr_t CookPatchNullChk2;
    extern uintptr_t CookPatchNullTgt1;
    extern uintptr_t CookPatchNullTgt2;
    extern uintptr_t CookPatchFireWr;
    extern uintptr_t ExpHandler;
}

typedef __int64 (__fastcall *Fn_CookShowPage)(__int64, __int64);
typedef bool    (__fastcall *Fn_CookHandler)(__int64, __int64, __int64);
typedef bool    (__fastcall *Fn_Handler)(__int64, __int64);

extern Fn_CookShowPage g_oCookShowPage;
extern const BYTE CookingHash[4];
extern const BYTE ExpeditionHash[4];
extern BYTE g_CookHandlerPrologue[8];
extern BYTE g_ExpHandlerPrologue[8];
extern bool g_CookReady;
extern volatile bool g_TrigCook;
extern volatile bool g_TrigExp;
extern DWORD g_LastCookTime;
extern DWORD g_LastExpTime;

uintptr_t FindHandlerByHash(uintptr_t dispBase, const BYTE hash[4]);
uintptr_t FindExpeditionHandler(uintptr_t dispBase, const BYTE hash[4]);
bool ResolveCookingPatches();
__int64 __fastcall hk_CookShowPage(__int64 a1, __int64 a2);
void DoCookingLogic();
void DoExpeditionLogic();
