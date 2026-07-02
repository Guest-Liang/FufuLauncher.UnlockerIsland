#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <atomic>
#include <mutex>
#include <vector>
#include <map>
#include <string>
#include <list>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <winsock2.h>

struct Il2CppString;

struct Vector3 { float x, y, z; };

struct __declspec(align(16)) Matrix4x4 {
    float m[4][4];
};

typedef int32_t (WINAPI *tGetFrameCount)();
typedef int32_t (WINAPI *tSetFrameCount)(int32_t);
typedef void (WINAPI *tSwitchInput)(void*);
typedef int32_t (WINAPI *tChangeFov)(void*, float);
typedef void (WINAPI *tSetupQuestBanner)(void*);
typedef void (WINAPI *tShowDamage)(void*, int, int, int, float, Il2CppString*, void*, void*, int);
typedef void (WINAPI *tCraftEntry)(void*);
typedef bool (WINAPI *tCraftPartner)(Il2CppString*, void*, void*, void*, void*);
typedef Il2CppString* (WINAPI *tFindString)(const char*);
typedef void* (WINAPI *tFindGameObject)(Il2CppString*);
typedef void (WINAPI *tSetActive)(void*, bool);
typedef bool (WINAPI *tEventCamera)(void*, void*);
typedef bool (WINAPI *tCheckCanEnter)();
typedef void (WINAPI *tOpenTeamPage)(bool);
typedef void (WINAPI *tOpenTeam)();
typedef __int64 (*tDisplayFog)(__int64, __int64);
typedef void* (WINAPI *tPlayerPerspective)(void*, float, void*);
typedef int32_t (WINAPI *tSetSyncCount)(bool);
typedef __int64 (WINAPI *tGameUpdate)(__int64, const char*);
typedef HRESULT(__stdcall* tPresent)(IDXGISwapChain*, UINT, UINT);
typedef HRESULT(__stdcall* tResizeBuffers)(IDXGISwapChain*, UINT, UINT, UINT, DXGI_FORMAT, UINT);
typedef BOOL (WINAPI* tQueryPerformanceCounter)(LARGE_INTEGER*);
typedef ULONGLONG (WINAPI* tGetTickCount64)();
typedef int (WSAAPI* tSend)(SOCKET s, const char* buf, int len, int flags);
typedef int (WSAAPI* tSendTo)(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen);
typedef HRESULT(__stdcall* tPresent1)(IDXGISwapChain* pSwapChain, UINT SyncInterval, UINT PresentFlags, const DXGI_PRESENT_PARAMETERS* pPresentParameters);
typedef bool (WINAPI *tGetActive)(void*);
typedef void (WINAPI *tActorManagerCtor)(void*);
typedef void* (WINAPI *tGetGlobalActor)(void*);
typedef void (WINAPI *tAvatarPaimonAppear)(void*, void*, bool);
typedef void* (*tGetComponent)(void*, Il2CppString*);
typedef Il2CppString* (*tGetText)(void*);
typedef void (WINAPI *tVoidFunc)(void*);
typedef Il2CppString* (*tGetName)(void*);
typedef void (WINAPI *tSetUid)(void*, uint32_t);
typedef __int64 (*FnStringNew)(const char*);
typedef void (*FnShowDialog)(__int64, __int64, __int64, __int64, int);
typedef void (*tCamera_GetC2W)(Matrix4x4* out_result, void* _this, void* method_info);
typedef void(__fastcall* tSetPos)(void* pTransform, Vector3* pPos);
typedef void* (__fastcall* tGetMainCamera)();
typedef void* (__fastcall* tGetTransform)(void* pComponent);
typedef void(__fastcall* tSetupResinList)(void* pThis);
typedef void (__fastcall *tButtonClicked)(void*);
typedef void (__fastcall *tClockPageBack)(void*, void*);

extern std::atomic<void*> o_GetFrameCount;
extern std::atomic<void*> o_SetFrameCount;
extern std::atomic<void*> o_ChangeFov;
extern std::atomic<void*> o_SetupQuestBanner;
extern std::atomic<void*> o_ShowDamage;
extern std::atomic<void*> o_CraftEntry;
extern std::atomic<void*> o_EventCamera;
extern std::atomic<void*> o_OpenTeam;
extern std::atomic<void*> o_DisplayFog;
extern std::atomic<void*> p_SwitchInput;
extern std::atomic<void*> p_FindString;
extern std::atomic<void*> p_CraftPartner;
extern std::atomic<void*> p_FindGameObject;
extern std::atomic<void*> o_SetActive;
extern std::atomic<void*> p_CheckCanEnter;
extern std::atomic<void*> p_OpenTeamPage;
extern std::atomic<void*> o_PlayerPerspective;
extern std::atomic<void*> o_SetSyncCount;
extern std::atomic<void*> o_GameUpdate;
extern std::atomic<void*> o_SetupResinList;
extern std::atomic<void*> o_ClockPageOk;
extern std::atomic<void*> p_ClockPageClose;
extern std::atomic<void*> p_ClockPageFinish;
extern std::atomic<void*> p_ClockPageBack;
extern std::atomic<void*> o_ActorManagerCtor;
extern std::atomic<void*> p_GetGlobalActor;
extern std::atomic<void*> p_AvatarPaimonAppear;
extern std::atomic<void*> p_CheckCanOpenMap;
extern std::atomic<void*> p_GetName;
extern std::atomic<void*> o_send;
extern std::atomic<void*> o_sendto;
extern std::atomic<void*> o_SetPos;
extern std::atomic<void*> p_GetActive;
extern std::atomic<void*> o_SetUid;
extern std::atomic<void*> p_StringNew;
extern std::atomic<void*> p_ShowDialog;

extern std::atomic<bool> g_RequestReloadPopup;
extern std::atomic<bool> g_GameUpdateInit;
extern std::atomic<bool> g_RequestCraft;
extern std::once_flag g_TouchInitOnce;

extern unsigned char originalCheckCanOpenMapBytes[5];
extern ID3D11DeviceContext* g_pd3dContext;
extern ID3D11RenderTargetView* g_mainRenderTargetView;
extern HWND g_hGameWindow_ImGui;
extern tResizeBuffers o_ResizeBuffers;
extern tPresent1 o_Present1;
extern tGetMainCamera call_GetMainCamera;
extern tGetTransform call_GetTransform;
extern tCamera_GetC2W call_Camera_GetC2W;
extern void* g_ActorManagerInstance;
extern uint32_t g_CurrentUID;

extern bool g_ShowCoordWindow;
extern bool g_ResistInBeyd;

extern std::list<std::wstring> GrassPrefix;

extern const float FC_BASE_SPEED;
extern const float FC_SHIFT_MULTIPLIER;
extern const float FC_CTRL_MULTIPLIER;
extern const float FC_ACCELERATION;
extern const float FC_FRICTION;

namespace FreeCamState {
    extern volatile float camX, camY, camZ;
    extern volatile float velX, velY, velZ;
    extern float targetVelX, targetVelY, targetVelZ;
    extern void* mainCameraTransform;
    extern bool isActive;
    extern bool isObjectSelectionMode;
    extern void* currentTargetTransform;
    extern std::vector<void*> capturedTransforms;
    extern std::mutex transformMutex;
    extern int selectionIndex;
    extern std::map<void*, ULONGLONG> activeTransformsMap;
    extern std::vector<void*> stableList;
}

extern std::atomic<bool> g_ShouldShowDialog;
extern std::string g_DialogText;
extern std::mutex g_DialogMutex;
extern std::atomic<bool> g_StopDialogPolling;
