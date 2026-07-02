#include "SharedState.h"

std::atomic<void*> o_GetFrameCount{ nullptr };
std::atomic<void*> o_SetFrameCount{ nullptr };
std::atomic<void*> o_ChangeFov{ nullptr };
std::atomic<void*> o_SetupQuestBanner{ nullptr };
std::atomic<void*> o_ShowDamage{ nullptr };
std::atomic<void*> o_CraftEntry{ nullptr };
std::atomic<void*> o_EventCamera{ nullptr };
std::atomic<void*> o_OpenTeam{ nullptr };
std::atomic<void*> o_DisplayFog{ nullptr };
std::atomic<void*> p_SwitchInput{ nullptr };
std::atomic<void*> p_FindString{ nullptr };
std::atomic<void*> p_CraftPartner{ nullptr };
std::atomic<void*> p_FindGameObject{ nullptr };
std::atomic<void*> o_SetActive{ nullptr };
std::atomic<void*> p_CheckCanEnter{ nullptr };
std::atomic<void*> p_OpenTeamPage{ nullptr };
std::atomic<void*> o_PlayerPerspective{ nullptr };
std::atomic<void*> o_SetSyncCount{ nullptr };
std::atomic<void*> o_GameUpdate{ nullptr };
std::atomic<void*> o_SetupResinList{ nullptr };
std::atomic<void*> o_ClockPageOk{ nullptr };
std::atomic<void*> p_ClockPageClose{ nullptr };
std::atomic<void*> p_ClockPageFinish{ nullptr };
std::atomic<void*> p_ClockPageBack{ nullptr };
std::atomic<void*> o_ActorManagerCtor{ nullptr };
std::atomic<void*> p_GetGlobalActor{ nullptr };
std::atomic<void*> p_AvatarPaimonAppear{ nullptr };
std::atomic<void*> p_CheckCanOpenMap{ nullptr };
std::atomic<void*> p_GetName{ nullptr };
std::atomic<void*> o_send{ nullptr };
std::atomic<void*> o_sendto{ nullptr };
std::atomic<void*> o_SetPos{ nullptr };
std::atomic<void*> p_GetActive{ nullptr };
std::atomic<void*> o_SetUid{ nullptr };
std::atomic<void*> p_StringNew{ nullptr };
std::atomic<void*> p_ShowDialog{ nullptr };

std::atomic<bool> g_RequestReloadPopup{ false };
std::atomic<bool> g_GameUpdateInit{ false };
std::atomic<bool> g_RequestCraft{ false };
std::once_flag g_TouchInitOnce;

unsigned char originalCheckCanOpenMapBytes[5] = {0};
ID3D11DeviceContext* g_pd3dContext = nullptr;
ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;
HWND g_hGameWindow_ImGui = nullptr;
tResizeBuffers o_ResizeBuffers = nullptr;
tPresent1 o_Present1 = nullptr;
tGetMainCamera call_GetMainCamera = nullptr;
tGetTransform call_GetTransform = nullptr;
tCamera_GetC2W call_Camera_GetC2W = nullptr;
void* g_ActorManagerInstance = nullptr;
uint32_t g_CurrentUID = 0;

bool g_ShowCoordWindow = false;
bool g_ResistInBeyd = false;

std::list<std::wstring> GrassPrefix {
    L"Area_Ndkl_",
    L"Area_Nt_",
    L"Area_Fd_",
    L"Area_Xm_",
    L"Area_Ly_",
    L"Stages_M",
    L"BigWorld_",
};

const float FC_BASE_SPEED = 0.045f;
const float FC_SHIFT_MULTIPLIER = 6.0f;
const float FC_CTRL_MULTIPLIER = 0.2f;
const float FC_ACCELERATION = 0.10f;
const float FC_FRICTION = 0.94f;

namespace FreeCamState {
    volatile float camX = 0.0f, camY = 0.0f, camZ = 0.0f;
    volatile float velX = 0.0f, velY = 0.0f, velZ = 0.0f;
    float targetVelX = 0.0f, targetVelY = 0.0f, targetVelZ = 0.0f;
    void* mainCameraTransform = nullptr;
    bool isActive = false;
    bool isObjectSelectionMode = false;
    void* currentTargetTransform = nullptr;
    std::vector<void*> capturedTransforms;
    std::mutex transformMutex;
    int selectionIndex = -1;
    std::map<void*, ULONGLONG> activeTransformsMap;
    std::vector<void*> stableList;
}
