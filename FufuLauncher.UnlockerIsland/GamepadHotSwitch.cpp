#include "GamepadHotSwitch.h"
#include "Config.h"
#include "HookWndProc.h"
#include <iostream>
#include <string>

GamepadHotSwitch::GamepadHotSwitch()
{
}

GamepadHotSwitch::~GamepadHotSwitch()
{
    Shutdown();
}

GamepadHotSwitch& GamepadHotSwitch::GetInstance()
{
    static GamepadHotSwitch instance;
    return instance;
}

bool GamepadHotSwitch::Initialize()
{
    if (m_hThread)
    {
        if (Config::Get().debug_console)
            std::cout << "[GamepadHotSwitch] Already initialized\n";
        return true;
    }
    
    GetCursorPos(&m_lastMousePos);
    m_lastMouseTime = GetTickCount64();
    m_lastMouseActivityTime = m_lastMouseTime;
    
    m_isExiting = false;
    m_hThread = CreateThread(nullptr, 0, [](LPVOID lpParam) -> DWORD {
        GamepadHotSwitch* pThis = static_cast<GamepadHotSwitch*>(lpParam);
        pThis->MainThread();
        return 0;
    }, this, 0, nullptr);
    
    if (!m_hThread)
    {
        if (Config::Get().debug_console)
            std::cout << "[GamepadHotSwitch] Failed to create thread\n";
        return false;
    }
    
    if (Config::Get().debug_console)
        std::cout << "[GamepadHotSwitch] Initialized successfully (Gamepad Recognition Disabled)\n";
    return true;
}

void GamepadHotSwitch::Shutdown()
{
    m_isExiting = true;
    m_enabled = false;
    
    if (m_hThread)
    {
        WaitForSingleObject(m_hThread, 1000);
        CloseHandle(m_hThread);
        m_hThread = nullptr;
    }
    
    if (Config::Get().debug_console)
        std::cout << "[GamepadHotSwitch] Shutdown\n";
}

void GamepadHotSwitch::SetEnabled(bool enabled)
{
    if (enabled == m_enabled)
        return;
    
    m_enabled = enabled;
    
    if (enabled)
    {
        if (!m_hThread)
        {
            Initialize();
        }
        if (Config::Get().debug_console)
            std::cout << "[GamepadHotSwitch] Enabled\n";
    }
    else
    {
        if (Config::Get().debug_console)
            std::cout << "[GamepadHotSwitch] Disabled\n";
    }
}

bool GamepadHotSwitch::IsEnabled() const
{
    return m_enabled;
}

void GamepadHotSwitch::ProcessWindowMessage(UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (!m_enabled)
        return;

    if (m_wKeySwitchCount < MAX_W_KEY_SWITCHES) 
    {
        if (msg == WM_KEYDOWN && wParam == 0x57)
        {
            if ((lParam & (1 << 30)) == 0)
            {
                m_wKeySwitchCount++;
                if (Config::Get().debug_console)
                {
                    std::cout << "[GamepadHotSwitch] Force switched by 'W' (" 
                              << m_wKeySwitchCount << "/" << MAX_W_KEY_SWITCHES << ")\n";
                }
                SendSwitchMessage(false, true);
            }
        }
    }

    switch (msg)
    {
    case WM_LBUTTONDOWN:
    case WM_RBUTTONDOWN:
    case WM_MBUTTONDOWN:
    case WM_MOUSEWHEEL:
    case WM_KEYDOWN:
    case WM_SYSKEYDOWN:
    case WM_INPUT:
        m_lastMouseActivityTime = GetTickCount64();
        break;
    }
}

bool GamepadHotSwitch::IsMouseActive() const
{
    ULONGLONG currentTime = GetTickCount64();
    ULONGLONG lastActivity = m_lastMouseActivityTime.load();
    
    if (currentTime - lastActivity < MOUSE_INACTIVITY_THRESHOLD_MS)
    {
        return true;
    }
    
    POINT currentPos;
    GetCursorPos(&currentPos);
    
    if (currentPos.x != m_lastMousePos.x || currentPos.y != m_lastMousePos.y)
    {
        return true;
    }
    
    return false;
}

void GamepadHotSwitch::SendSwitchMessage(bool toGamepad, bool force)
{
    if (!force && isGamepadMode == toGamepad)
        return;

    isGamepadMode = toGamepad;

    HWND hWnd = GetUnityMainWindow();
    if (hWnd && !toGamepad)
    {
        PostMessageW(hWnd, WM_MOUSE_ACTIVATED, (WPARAM)0, (LPARAM)0);
    }
}

void GamepadHotSwitch::MainThread()
{
    if (m_isExiting)
        return;
    
    if (Config::Get().debug_console)
        std::cout << "[GamepadHotSwitch] Main thread started\n";
    
    static bool lastWKeyPressed = false;
    
    while (!m_isExiting)
    {
        if (!m_enabled)
        {
            Sleep(100);
            continue;
        }
        
        if (m_wKeySwitchCount < MAX_W_KEY_SWITCHES)
        {
            bool currentWKeyPressed = (GetAsyncKeyState(0x57) & 0x8000) != 0;
            
            if (currentWKeyPressed && !lastWKeyPressed)
            {
                m_wKeySwitchCount++;
                if (Config::Get().debug_console)
                    std::cout << "[GamepadHotSwitch] MainThread: Force switched by 'W'\n";
                
                SendSwitchMessage(false, true);
            }
            lastWKeyPressed = currentWKeyPressed;
        }
        
        if (IsMouseActive())
        {
            SendSwitchMessage(false);
        }
        
        GetCursorPos(&m_lastMousePos);
        
        Sleep(50);
    }
    
    if (Config::Get().debug_console)
        std::cout << "[GamepadHotSwitch] Main thread exiting\n";
}