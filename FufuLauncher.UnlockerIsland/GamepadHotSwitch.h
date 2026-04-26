#pragma once

#include <windows.h>
#include <atomic>
#include <thread>

class GamepadHotSwitch
{
public:
    static GamepadHotSwitch& GetInstance();

    bool Initialize();
    void Shutdown();
    void SetEnabled(bool enabled);
    bool IsEnabled() const;
    void ProcessWindowMessage(UINT msg, WPARAM wParam, LPARAM lParam);

private:
    GamepadHotSwitch();
    ~GamepadHotSwitch();
    
    GamepadHotSwitch(const GamepadHotSwitch&) = delete;
    GamepadHotSwitch& operator=(const GamepadHotSwitch&) = delete;
    
    // 在 GamepadHotSwitch.h 的 private 区域修改：
    void MainThread();
    bool IsMouseActive() const;
    void SendSwitchMessage(bool toGamepad, bool force = false); // 添加 force 参数

private:
    std::atomic<bool> m_isExiting{false};
    std::atomic<bool> m_enabled{false};

    std::atomic<int> m_wKeySwitchCount{0};
    static constexpr int MAX_W_KEY_SWITCHES = 5;
    
    HANDLE m_hThread{nullptr};
    
    POINT m_lastMousePos{0, 0};
    ULONGLONG m_lastMouseTime = 0;
    std::atomic<ULONGLONG> m_lastMouseActivityTime{0};

    bool isGamepadMode = false;
    
    static constexpr DWORD SWITCH_DELAY_MS = 100;
    static constexpr DWORD MOUSE_INACTIVITY_THRESHOLD_MS = 2000;
};