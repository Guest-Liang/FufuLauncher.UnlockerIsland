#include "GamepadHotSwitch.h"
#include "Config.h"
#include "HookWndProc.h"
#include <iostream>
#include <string>

#pragma comment(lib, "dinput8.lib")
#pragma comment(lib, "dxguid.lib")

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
            std::cout << "[GamepadHotSwitch] Already initialized" << std::endl;
        return true;
    }
    
    m_hXInput = LoadLibraryW(L"XInput1_4.dll");
    if (!m_hXInput) m_hXInput = LoadLibraryW(L"XInput9_1_0.dll");
    if (!m_hXInput) m_hXInput = LoadLibraryW(L"XInput1_3.dll");
    
    if (!m_hXInput)
    {
        if (Config::Get().debug_console)
            std::cout << "[GamepadHotSwitch] Failed to load XInput library" << std::endl;
    }
    else
    {
        m_XInputGetState = (DWORD(WINAPI*)(DWORD, XINPUT_STATE*))GetProcAddress(m_hXInput, "XInputGetState");
        if (!m_XInputGetState)
        {
            FreeLibrary(m_hXInput);
            m_hXInput = nullptr;
            if (Config::Get().debug_console)
                std::cout << "[GamepadHotSwitch] Failed to get XInputGetState function" << std::endl;
        }
    }

    if (!InitializeDirectInput())
    {
        if (Config::Get().debug_console)
            std::cout << "[GamepadHotSwitch] DirectInput initialization failed or no DirectInput devices found" << std::endl;
    }
    
    if (!m_hXInput && m_directInputDevices.empty())
    {
        if (Config::Get().debug_console)
            std::cout << "[GamepadHotSwitch] Warning: No gamepad support available" << std::endl;
        return false;
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
        if (m_hXInput) { FreeLibrary(m_hXInput); m_hXInput = nullptr; }
        ShutdownDirectInput();
        if (Config::Get().debug_console)
            std::cout << "[GamepadHotSwitch] Failed to create thread" << std::endl;
        return false;
    }
    
    if (Config::Get().debug_console)
        std::cout << "[GamepadHotSwitch] Initialized successfully" << std::endl;
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
    
    if (m_hXInput)
    {
        FreeLibrary(m_hXInput);
        m_hXInput = nullptr;
        m_XInputGetState = nullptr;
    }

    ShutdownDirectInput();
    
    if (Config::Get().debug_console)
        std::cout << "[GamepadHotSwitch] Shutdown" << std::endl;
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
            std::cout << "[GamepadHotSwitch] Enabled" << std::endl;
    }
    else
    {
        if (Config::Get().debug_console)
            std::cout << "[GamepadHotSwitch] Disabled" << std::endl;
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

bool GamepadHotSwitch::IsControllerActive(const XINPUT_STATE& state) const
{
    if (state.Gamepad.wButtons != 0)
        return true;

    if (state.Gamepad.bLeftTrigger > TRIGGER_THRESHOLD ||
        state.Gamepad.bRightTrigger > TRIGGER_THRESHOLD)
        return true;

    short lx = state.Gamepad.sThumbLX;
    short ly = state.Gamepad.sThumbLY;
    if (abs(lx) > THUMB_L_THRESHOLD || abs(ly) > THUMB_L_THRESHOLD)
        return true;

    short rx = state.Gamepad.sThumbRX;
    short ry = state.Gamepad.sThumbRY;
    if (abs(rx) > THUMB_R_THRESHOLD || abs(ry) > THUMB_R_THRESHOLD)
        return true;

    return false;
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

void GamepadHotSwitch::SendSwitchMessage(bool toGamepad)
{
    if (isGamepadMode == toGamepad)
        return;

    isGamepadMode = toGamepad;

    HWND hWnd = GetUnityMainWindow();
    if (hWnd)
    {
         PostMessageW(hWnd,
            toGamepad ? WM_GAMEPAD_ACTIVATED : WM_MOUSE_ACTIVATED,
            (WPARAM)0, (LPARAM)0);
    }
}

void GamepadHotSwitch::MainThread()
{
    if (m_isExiting)
        return;
    
    if (Config::Get().debug_console)
        std::cout << "[GamepadHotSwitch] Main thread started" << std::endl;
    
    while (!m_isExiting)
    {
        if (!m_enabled)
        {
            Sleep(100);
            continue;
        }
        
        bool anyGamepadActive = false;
        
        for (DWORD i = 0; i < XUSER_MAX_COUNT; ++i)
        {
            XINPUT_STATE state = {};
            if (m_XInputGetState && m_XInputGetState(i, &state) == ERROR_SUCCESS)
            {
                if (IsControllerActive(state))
                {
                    anyGamepadActive = true;
                    m_lastGamepadActivityTime = GetTickCount64();
                    break;
                }
            }
        }

        if (!anyGamepadActive && IsDirectInputControllerActive())
        {
            anyGamepadActive = true;
            m_lastGamepadActivityTime = GetTickCount64();
        }
        
        bool mouseCurrentlyActive = IsMouseActive();
        
        ULONGLONG currentTime = GetTickCount64();
        
        if (anyGamepadActive)
        {
            SendSwitchMessage(true);
        }
        else if (mouseCurrentlyActive)
        {
            if (currentTime - m_lastGamepadActivityTime > GAMEPAD_INACTIVITY_THRESHOLD_MS)
            {
                SendSwitchMessage(false);
            }
        }
        
        GetCursorPos(&m_lastMousePos);
        
        Sleep(50);
    }
    
    if (Config::Get().debug_console)
        std::cout << "[GamepadHotSwitch] Main thread exiting" << std::endl;
}

static BOOL CALLBACK EnumDirectInputDevicesCallback(LPCDIDEVICEINSTANCEW lpddi, LPVOID pvRef)
{
    GamepadHotSwitch* pThis = static_cast<GamepadHotSwitch*>(pvRef);
    return pThis->InitializeDirectInputDevice(lpddi);
}

bool GamepadHotSwitch::InitializeDirectInput()
{
    m_hDirectInput = LoadLibraryW(L"dinput8.dll");
    if (!m_hDirectInput) return false;

    typedef HRESULT(WINAPI* DirectInput8CreateFn)(HINSTANCE, DWORD, REFIID, LPVOID*, LPUNKNOWN);
    DirectInput8CreateFn pDirectInput8Create = (DirectInput8CreateFn)GetProcAddress(m_hDirectInput, "DirectInput8Create");

    if (!pDirectInput8Create)
    {
        FreeLibrary(m_hDirectInput);
        m_hDirectInput = nullptr;
        return false;
    }

    HRESULT hr = pDirectInput8Create(GetModuleHandle(nullptr), DIRECTINPUT_VERSION,
                                     IID_IDirectInput8W, (LPVOID*)&m_pDirectInput, nullptr);
    if (FAILED(hr) || !m_pDirectInput)
    {
        FreeLibrary(m_hDirectInput);
        m_hDirectInput = nullptr;
        return false;
    }

    hr = m_pDirectInput->EnumDevices(DI8DEVCLASS_GAMECTRL, EnumDirectInputDevicesCallback, this, DIEDFL_ATTACHEDONLY);
    if (FAILED(hr)) return false;

    if (Config::Get().debug_console && !m_directInputDevices.empty())
        std::cout << "[GamepadHotSwitch] DirectInput initialized with " << m_directInputDevices.size() << " device(s)" << std::endl;

    return !m_directInputDevices.empty();
}

BOOL GamepadHotSwitch::InitializeDirectInputDevice(LPCDIDEVICEINSTANCEW lpddi)
{
    if (!m_pDirectInput) return DIENUM_STOP;

    IDirectInputDevice8W* pDevice = nullptr;
    HRESULT hr = m_pDirectInput->CreateDevice(lpddi->guidInstance, &pDevice, nullptr);

    if (FAILED(hr) || !pDevice) return DIENUM_CONTINUE;

    hr = pDevice->SetDataFormat(&c_dfDIJoystick2);
    if (FAILED(hr)) { pDevice->Release(); return DIENUM_CONTINUE; }

    hr = pDevice->SetCooperativeLevel(nullptr, DISCL_NONEXCLUSIVE | DISCL_BACKGROUND);
    if (FAILED(hr)) { pDevice->Release(); return DIENUM_CONTINUE; }

    DIPROPRANGE diprg;
    diprg.diph.dwSize       = sizeof(DIPROPRANGE);
    diprg.diph.dwHeaderSize = sizeof(DIPROPHEADER);
    diprg.diph.dwHow        = DIPH_DEVICE;
    diprg.diph.dwObj        = 0;
    diprg.lMin              = 0;
    diprg.lMax              = 65535;
    
    pDevice->SetProperty(DIPROP_RANGE, &diprg.diph);

    hr = pDevice->Acquire();
    if (FAILED(hr)) { pDevice->Release(); return DIENUM_CONTINUE; }

    m_directInputDevices.push_back(pDevice);
    return DIENUM_CONTINUE;
}

void GamepadHotSwitch::ShutdownDirectInput()
{
    for (auto* pDevice : m_directInputDevices)
    {
        if (pDevice)
        {
            pDevice->Unacquire();
            pDevice->Release();
        }
    }
    m_directInputDevices.clear();

    if (m_pDirectInput)
    {
        m_pDirectInput->Release();
        m_pDirectInput = nullptr;
    }

    if (m_hDirectInput)
    {
        FreeLibrary(m_hDirectInput);
        m_hDirectInput = nullptr;
    }
}

bool GamepadHotSwitch::IsDirectInputDeviceActive(IDirectInputDevice8W* pDevice)
{
    if (!pDevice) return false;

    DIJOYSTATE2 state;
    HRESULT hr = pDevice->GetDeviceState(sizeof(DIJOYSTATE2), &state);

    if (FAILED(hr))
    {
        hr = pDevice->Acquire();
        if (SUCCEEDED(hr))
        {
            hr = pDevice->GetDeviceState(sizeof(DIJOYSTATE2), &state);
        }
        if (FAILED(hr)) return false;
    }

    const LONG CENTER = 32768;
    if (abs(state.lX - CENTER) > THUMB_L_THRESHOLD || abs(state.lY - CENTER) > THUMB_L_THRESHOLD) return true;
    if (abs(state.lZ - CENTER) > THUMB_R_THRESHOLD || abs(state.lRz - CENTER) > THUMB_R_THRESHOLD) return true;

    const LONG TRIGGER_SCALED = (TRIGGER_THRESHOLD * 65535L) / 255L;
    if (state.lRx > TRIGGER_SCALED || state.lRy > TRIGGER_SCALED) return true;

    return false;
}

bool GamepadHotSwitch::IsDirectInputControllerActive()
{
    for (auto* pDevice : m_directInputDevices)
    {
        if (IsDirectInputDeviceActive(pDevice)) return true;
    }
    return false;
}
