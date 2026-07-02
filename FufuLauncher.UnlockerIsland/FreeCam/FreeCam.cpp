#include "FreeCam.h"
#include "../Patterns/Patterns.h"
#include "../Config/Config.h"
#include "../Core/Utils.h"
#include <iostream>
#include <sstream>

void InitCameraMatrixAddress() {
    static bool isAddrInitialized = false;
    if (!isAddrInitialized) {
        uintptr_t base = (uintptr_t)GetModuleHandle(NULL);
        if (base) {
            std::string offsetStr = Offsets::CameraGetC2WOffset;
            uintptr_t offsetVal = 0;
            std::stringstream ss;
            ss << std::hex << offsetStr;
            ss >> offsetVal;
            call_Camera_GetC2W = (tCamera_GetC2W)(base + offsetVal);
        }
        isAddrInitialized = true;
    }
}

bool TryGetCameraMatrix(float& out_rightX, float& out_rightY, float& out_rightZ,
                        float& out_forwardX, float& out_forwardY, float& out_forwardZ) {
    InitCameraMatrixAddress();

    if (!IsValidCodePtr(call_GetMainCamera) || !IsValidCodePtr(call_Camera_GetC2W)) {
        return false;
    }

    __try {
        void* pCamera = call_GetMainCamera();
        if (pCamera && !IsBadReadPtr(pCamera, sizeof(void*))) {
            Matrix4x4 mat;
            call_Camera_GetC2W(&mat, pCamera, nullptr);

            out_rightX = mat.m[0][0];
            out_rightY = mat.m[1][0];
            out_rightZ = mat.m[2][0];

            out_forwardX = -mat.m[0][2];
            out_forwardY = -mat.m[1][2];
            out_forwardZ = -mat.m[2][2];

            return true;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return false;
}

void UpdateFreeCamPhysics() {
    auto& cfg = Config::Get();
    ULONGLONG currentTick = GetTickCount64();

    HWND hForeground = GetForegroundWindow();
    DWORD foregroundProcessId = 0;
    if (hForeground) {
        GetWindowThreadProcessId(hForeground, &foregroundProcessId);
    }
    bool isFocused = (foregroundProcessId == GetCurrentProcessId());

    static ULONGLONG f6PressStart = 0;
    static bool f6Handled = false;

    if (isFocused && (GetAsyncKeyState(VK_F6) & 0x8000)) {
        if (f6PressStart == 0) {
            f6PressStart = currentTick;
            f6Handled = false;
        } else if (!f6Handled && currentTick - f6PressStart >= 3000) {

            bool newState = !g_ShowCoordWindow;

            g_ShowCoordWindow = newState;
            FreeCamState::isObjectSelectionMode = newState;

            if (!newState) {
                FreeCamState::currentTargetTransform = nullptr;
                {
                    std::lock_guard lock(FreeCamState::transformMutex);
                    FreeCamState::activeTransformsMap.clear();
                    FreeCamState::stableList.clear();
                }
            }

            f6Handled = true;
            std::cout << "[System] Debug Mode & Window: " << (newState ? "ON" : "OFF") << std::endl;
        }
    } else {
        f6PressStart = 0;
        f6Handled = false;
    }

    if (FreeCamState::isObjectSelectionMode) {
        std::lock_guard lock(FreeCamState::transformMutex);

        for (auto it = FreeCamState::activeTransformsMap.begin(); it != FreeCamState::activeTransformsMap.end(); ) {
            if (currentTick - it->second > 1000) {
                it = FreeCamState::activeTransformsMap.erase(it);
            } else {
                ++it;
            }
        }

        FreeCamState::stableList.clear();
        for (auto const& [ptr, time] : FreeCamState::activeTransformsMap) {
            FreeCamState::stableList.push_back(ptr);
        }

        static ULONGLONG lastSwitchTick = 0;
        if (currentTick - lastSwitchTick > 200) {
            bool pressPrev = isFocused && (GetAsyncKeyState(VK_DIVIDE) & 0x8000);
            bool pressNext = isFocused && (GetAsyncKeyState(VK_MULTIPLY) & 0x8000);

            if (pressPrev || pressNext) {
                lastSwitchTick = currentTick;

                int currentIndex = -1;
                if (FreeCamState::currentTargetTransform != nullptr) {
                    for (int i = 0; i < (int)FreeCamState::stableList.size(); ++i) {
                        if (FreeCamState::stableList[i] == FreeCamState::currentTargetTransform) {
                            currentIndex = i;
                            break;
                        }
                    }
                }

                int total = (int)FreeCamState::stableList.size();
                int nextIndex = currentIndex;

                if (pressPrev) {
                    nextIndex--;
                    if (nextIndex < -1) nextIndex = total - 1;
                }
                else if (pressNext) {
                    nextIndex++;
                    if (nextIndex >= total) nextIndex = -1;
                }

                if (nextIndex == -1 || total == 0) {
                    FreeCamState::currentTargetTransform = nullptr;
                    std::cout << "[FreeCam] Selected: Main Camera (Total Objects: " << total << ")" << std::endl;
                } else {
                    FreeCamState::currentTargetTransform = FreeCamState::stableList[nextIndex];
                    std::cout << "[FreeCam] Selected Object " << (nextIndex + 1) << "/" << total
                              << " (Ptr: " << FreeCamState::currentTargetTransform << ")" << std::endl;
                    FreeCamState::velX = FreeCamState::velY = FreeCamState::velZ = 0.0f;
                }
            }
        }
    }

    static bool lastToggleKey = false;
    bool currToggleKey = isFocused && (GetAsyncKeyState(cfg.free_cam_key) & 0x8000);
    if (currToggleKey && !lastToggleKey) {
        if (!FreeCamState::isActive) {
            bool canEnable = true;
            InitCameraMatrixAddress();

            if (Config::Get().enable_free_cam_movement_fix) {
                if (!IsValidCodePtr(call_GetMainCamera) || !IsValidCodePtr(call_Camera_GetC2W)) {
                    canEnable = false;
                }
            }

            if (!IsValidCodePtr((void*)o_SetPos.load()) || !IsValidCodePtr(call_GetMainCamera) || !IsValidCodePtr(call_GetTransform)) {
                canEnable = false;
            }

            if (canEnable) {
                FreeCamState::isActive = true;
                FreeCamState::velX = FreeCamState::velY = FreeCamState::velZ = 0.0f;
                std::cout << "[FreeCam] Enabled." << std::endl;
            } else {
                std::cout << "[FreeCam] Warning: Hook functions or offsets are invalid. FreeCam cannot be enabled to prevent crashes." << std::endl;
            }
        } else {
            FreeCamState::isActive = false;
            FreeCamState::velX = FreeCamState::velY = FreeCamState::velZ = 0.0f;
            std::cout << "[FreeCam] Disabled." << std::endl;
        }
    }
    lastToggleKey = currToggleKey;

    if (isFocused && (GetAsyncKeyState(cfg.free_cam_reset_key) & 0x8000)) {
        FreeCamState::mainCameraTransform = nullptr;
    }

    if (!FreeCamState::isActive) return;

    float forwardX = 0, forwardY = 0, forwardZ = 1;
    float rightX = 1, rightY = 0, rightZ = 0;
    bool gotMatrix = false;

    if (Config::Get().enable_free_cam_movement_fix) {
        gotMatrix = TryGetCameraMatrix(rightX, rightY, rightZ, forwardX, forwardY, forwardZ);
    }

    float currentPower = FC_BASE_SPEED;
    if (isFocused) {
        if (GetAsyncKeyState(cfg.free_cam_speed_up) & 0x8000)   currentPower *= FC_SHIFT_MULTIPLIER;
        if (GetAsyncKeyState(cfg.free_cam_speed_down) & 0x8000) currentPower *= FC_CTRL_MULTIPLIER;
    }

    float inputForward = 0.0f;
    float inputRight = 0.0f;
    float inputUp = 0.0f;

    if (isFocused) {
        if (GetAsyncKeyState(cfg.free_cam_forward) & 0x8000)   inputForward += 1.0f;
        if (GetAsyncKeyState(cfg.free_cam_backward) & 0x8000)  inputForward -= 1.0f;
        if (GetAsyncKeyState(cfg.free_cam_left) & 0x8000)      inputRight -= 1.0f;
        if (GetAsyncKeyState(cfg.free_cam_right) & 0x8000)     inputRight += 1.0f;
        if (GetAsyncKeyState(cfg.free_cam_up) & 0x8000)        inputUp += 1.0f;
        if (GetAsyncKeyState(cfg.free_cam_down) & 0x8000)      inputUp -= 1.0f;
    }
    float targetVelX = 0.0f, targetVelY = 0.0f, targetVelZ = 0.0f;

    if (gotMatrix) {
        targetVelX += forwardX * inputForward;
        targetVelY += forwardY * inputForward;
        targetVelZ += forwardZ * inputForward;

        targetVelX += rightX * inputRight;
        targetVelY += rightY * inputRight;
        targetVelZ += rightZ * inputRight;

        targetVelY += inputUp;
    } else {
        targetVelZ += inputForward;
        targetVelX += inputRight;
        targetVelY += inputUp;
    }

    targetVelX *= currentPower;
    targetVelY *= currentPower;
    targetVelZ *= currentPower;

    FreeCamState::velX += (targetVelX - FreeCamState::velX) * FC_ACCELERATION;
    FreeCamState::velY += (targetVelY - FreeCamState::velY) * FC_ACCELERATION;
    FreeCamState::velZ += (targetVelZ - FreeCamState::velZ) * FC_ACCELERATION;

    if (abs(inputForward) < 0.1f && abs(inputRight) < 0.1f && abs(inputUp) < 0.1f) {
        FreeCamState::velX *= FC_FRICTION;
        FreeCamState::velY *= FC_FRICTION;
        FreeCamState::velZ *= FC_FRICTION;
        if (abs(FreeCamState::velX) < 0.001f) FreeCamState::velX = 0.0f;
        if (abs(FreeCamState::velY) < 0.001f) FreeCamState::velY = 0.0f;
        if (abs(FreeCamState::velZ) < 0.001f) FreeCamState::velZ = 0.0f;
    }

    FreeCamState::camX += FreeCamState::velX;
    FreeCamState::camY += FreeCamState::velY;
    FreeCamState::camZ += FreeCamState::velZ;
}

static void ClockPageOk_SafeLogic(void* pThis, bool& out_handled) {
    out_handled = false;
    auto& cfg = Config::Get();
    auto orig = (tButtonClicked)o_ClockPageOk.load();

    if (cfg.debug_console) {
        std::cout << "[Clock Debug] OK Button Hook Triggered!" << std::endl;
    }

    if (cfg.enable_clock_speedup) {
        out_handled = true;

        if (orig && !IsBadReadPtr((void*)orig, 1)) {
            orig(pThis);
        }

        auto finishFunc = (tButtonClicked)p_ClockPageFinish.load();
        if (finishFunc && !IsBadReadPtr((void*)finishFunc, 1)) {
            if (cfg.debug_console) {
                std::cout << "[Clock Debug] Forcing Finish UI..." << std::endl;
            }
            finishFunc(pThis);
        }

        auto backFunc = (tClockPageBack)p_ClockPageBack.load();
        if (backFunc && !IsBadReadPtr((void*)backFunc, 1)) {
            if (cfg.debug_console) {
                std::cout << "[Clock Debug] Forcing Back UI..." << std::endl;
            }
            backFunc(pThis, nullptr);
            return;
        }

        auto closeBtnFunc = (tButtonClicked)p_ClockPageClose.load();
        if (!closeBtnFunc || IsBadReadPtr((void*)closeBtnFunc, 1)) {
            return;
        }
        if (cfg.debug_console) {
            std::cout << "[Clock Debug] Forcing Close UI..." << std::endl;
        }

        closeBtnFunc(pThis);
    }
}

void WINAPI hk_ClockPageOk(void* pThis) {
    auto orig = (tButtonClicked)o_ClockPageOk.load();

    if (!pThis || IsBadReadPtr(pThis, sizeof(void*))) {
        if (orig && IsValidCodePtr(orig)) {
            __try { orig(pThis); } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        return;
    }

    bool handled = false;

    __try {
        ClockPageOk_SafeLogic(pThis, handled);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        handled = false;
    }

    if (!handled && orig && IsValidCodePtr(orig)) {
        __try {
            orig(pThis);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
}

static void SetPos_SafeLogic(void* pTransform, Vector3* pPos, bool& out_handled) {
    out_handled = false;

    static int checkTimer = 0;
    checkTimer++;
    if (FreeCamState::mainCameraTransform == nullptr || checkTimer > 100) {
        checkTimer = 0;
        if (IsValidCodePtr(call_GetMainCamera) && IsValidCodePtr(call_GetTransform)) {
            void* pCamInfo = call_GetMainCamera();
            if (pCamInfo && !IsBadReadPtr(pCamInfo, sizeof(void*))) {
                void* realTrans = call_GetTransform(pCamInfo);
                if (realTrans && !IsBadReadPtr(realTrans, sizeof(void*))) {
                    FreeCamState::mainCameraTransform = realTrans;
                }
            }
        }
    }

    if (FreeCamState::isObjectSelectionMode) {
        std::lock_guard lock(FreeCamState::transformMutex);
        FreeCamState::activeTransformsMap[pTransform] = GetTickCount64();
    }

    void* targetTransform = FreeCamState::mainCameraTransform;
    if (FreeCamState::isObjectSelectionMode && FreeCamState::currentTargetTransform != nullptr) {
        targetTransform = FreeCamState::currentTargetTransform;
    }

    if (targetTransform && pTransform == targetTransform) {
        static void* lastControlledTarget = nullptr;

        if (targetTransform != lastControlledTarget) {
            FreeCamState::camX = pPos->x;
            FreeCamState::camY = pPos->y;
            FreeCamState::camZ = pPos->z;
            lastControlledTarget = targetTransform;
        }

        if (!FreeCamState::isActive) {
            FreeCamState::camX = pPos->x;
            FreeCamState::camY = pPos->y;
            FreeCamState::camZ = pPos->z;
            FreeCamState::velX = FreeCamState::velY = FreeCamState::velZ = 0.0f;
        }

        if (FreeCamState::isActive) {
            Vector3 myPos;
            myPos.x = FreeCamState::camX;
            myPos.y = FreeCamState::camY;
            myPos.z = FreeCamState::camZ;

            auto orig = (tSetPos)o_SetPos.load();
            if (orig && IsValidCodePtr(orig)) {
                orig(pTransform, &myPos);
            }
            out_handled = true;
            return;
        }
    }
}

void __fastcall hk_SetPos(void* pTransform, Vector3* pPos) {
    auto orig = (tSetPos)o_SetPos.load();

    if (!pTransform || !pPos || IsBadReadPtr(pTransform, sizeof(void*)) || IsBadReadPtr(pPos, sizeof(Vector3))) {
        if (orig && IsValidCodePtr(orig)) {
            __try { orig(pTransform, pPos); } __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        return;
    }

    bool handled = false;
    __try {
        SetPos_SafeLogic(pTransform, pPos, handled);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        handled = false;
        FreeCamState::isActive = false;
    }

    if (!handled && orig && IsValidCodePtr(orig)) {
        __try {
            orig(pTransform, pPos);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            FreeCamState::isActive = false;
        }
    }
}
