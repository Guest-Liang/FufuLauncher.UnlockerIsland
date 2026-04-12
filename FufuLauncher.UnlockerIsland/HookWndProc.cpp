#include "HookWndProc.h"
#include "GamepadHotSwitch.h"
#include "Config.h"
#include "Scanner.h"
#include "EncryptedData.h"
#include <iostream>
#include <commctrl.h>
#pragma comment(lib, "comctl32.lib")
#include <sstream>

static HWND g_hUnityWindow = nullptr;
static bool g_subclassInstalled = false;
static UINT_PTR g_subclassId = 1;

LPVOID switchInputDeviceToTouchScreen = nullptr;
LPVOID switchInputDeviceToJoypad = nullptr;
LPVOID switchInputDeviceToKeyboard = nullptr;

LRESULT CALLBACK WindowSubclassProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData)
{
    switch (uMsg)
    {
    case WM_LBUTTONDOWN:
    case WM_RBUTTONDOWN:
    case WM_MBUTTONDOWN:
    case WM_MOUSEWHEEL:
    case WM_KEYDOWN:
    case WM_SYSKEYDOWN:
    case WM_INPUT:
        if (GamepadHotSwitch::GetInstance().IsEnabled())
        {
            if (uMsg == WM_INPUT)
            {
                UINT dwSize = 40;
                static BYTE lpb[40];
                if (GetRawInputData((HRAWINPUT)lParam, RID_INPUT, lpb, &dwSize, sizeof(RAWINPUTHEADER)) != (UINT)-1)
                {
                    RAWINPUT* raw = (RAWINPUT*)lpb;
                    if (raw->header.dwType == RIM_TYPEMOUSE && 
                       (raw->data.mouse.lLastX != 0 || raw->data.mouse.lLastY != 0))
                    {
                        GamepadHotSwitch::GetInstance().ProcessWindowMessage(uMsg, wParam, lParam);
                    }
                }
            }
            else
            {
                GamepadHotSwitch::GetInstance().ProcessWindowMessage(uMsg, wParam, lParam);
            }
        }
        break;
        
    case WM_GAMEPAD_ACTIVATED:
        HandleSwitchToGamepad();
        return 0;
        
    case WM_MOUSE_ACTIVATED:
        HandleSwitchToKeyboardMouse();
        return 0;
    }
    
    return DefSubclassProc(hWnd, uMsg, wParam, lParam);
}

void HandleSwitchToGamepad()
{
    if (switchInputDeviceToJoypad)
    {
        typedef void(*SwitchInputDeviceToJoypadFn)(void*);
        SwitchInputDeviceToJoypadFn switchInput = (SwitchInputDeviceToJoypadFn)switchInputDeviceToJoypad;
        
        __try
        {
            if (Config::Get().debug_console)
                std::cout << "[HookWndProc] Switched to gamepad input" << '\n';
            switchInput(nullptr);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            if (Config::Get().debug_console)
                std::cout << "[HookWndProc] CRITICAL EXCEPTION in SwitchInputDeviceToJoypad! Code: 0x" << std::hex << GetExceptionCode() << std::dec << '\n';
        }
    }
    else
    {
        if (Config::Get().debug_console)
            std::cout << "[HookWndProc] switchInputDeviceToJoypad function not available" << '\n';
    }
}

void HandleSwitchToKeyboardMouse()
{
    if (switchInputDeviceToKeyboard)
    {
        typedef void(*SwitchInputDeviceToKeyboardMouseFn)(void*);
        SwitchInputDeviceToKeyboardMouseFn switchInput = (SwitchInputDeviceToKeyboardMouseFn)switchInputDeviceToKeyboard;
        
        __try
        {
            if (Config::Get().debug_console)
                std::cout << "[HookWndProc] Attempting to switch to keyboard/mouse input..." << '\n';
            switchInput(nullptr);
            if (Config::Get().debug_console)
                std::cout << "[HookWndProc] Switched to keyboard/mouse input successfully" << '\n';
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            if (Config::Get().debug_console)
                std::cout << "[HookWndProc] CRITICAL EXCEPTION in SwitchInputDeviceToKeyboard! Code: 0x" << std::hex << GetExceptionCode() << std::dec << '\n';
        }
    }
    else
    {
        if (Config::Get().debug_console)
            std::cout << "[HookWndProc] switchInputDeviceToKeyboard function not available" << '\n';
    }
}
 
bool InstallWindowSubclass()
{
    if (!g_hUnityWindow || g_subclassInstalled)
    {
        return false;
    }
    
    if (SetWindowSubclass(g_hUnityWindow, WindowSubclassProc, g_subclassId, 0))
    {
        g_subclassInstalled = true;
        
        RAWINPUTDEVICE Rid[1];
        Rid[0].usUsagePage = 0x01; 
        Rid[0].usUsage = 0x02;
        Rid[0].dwFlags = RIDEV_INPUTSINK;   
        Rid[0].hwndTarget = g_hUnityWindow;
        RegisterRawInputDevices(Rid, 1, sizeof(Rid[0]));

        if (Config::Get().debug_console)
            std::cout << "[HookWndProc] Window subclass installed successfully" << '\n';
        return true;
    }
    
    DWORD error = GetLastError();
    if (Config::Get().debug_console)
        std::cout << "[HookWndProc] Failed to install window subclass: " << error << '\n';
    return false;
}

bool RemoveWindowSubclass()
{
    if (!g_hUnityWindow || !g_subclassInstalled)
    {
        return false;
    }
    
    if (::RemoveWindowSubclass(g_hUnityWindow, WindowSubclassProc, g_subclassId))
    {
        g_subclassInstalled = false;
        if (Config::Get().debug_console)
            std::cout << "[HookWndProc] Window subclass removed successfully" << '\n';
        return true;
    }
    
    DWORD error = GetLastError();
    if (Config::Get().debug_console)
        std::cout << "[HookWndProc] Failed to remove window subclass: " << error << '\n';
    return false;
}

void SetUnityMainWindow(HWND hWnd)
{
    if (g_hUnityWindow != hWnd)
    {
        if (g_subclassInstalled)
        {
            RemoveWindowSubclass();
        }
        
        g_hUnityWindow = hWnd;
        
        if (g_hUnityWindow)
        {
            InstallWindowSubclass();
        }
    }
}

HWND GetUnityMainWindow()
{
    return g_hUnityWindow;
}

static uintptr_t StringToAddr(const std::string& hexStr) {
    if (hexStr.empty()) return 0;
    uintptr_t addr = 0;
    std::stringstream ss;
    ss << std::hex << hexStr;
    ss >> addr;
    return addr;
}

void InitializeWndProcHooks()
{
    uintptr_t base = (uintptr_t)GetModuleHandle(NULL);
    
    if (base)
    {
        if (!switchInputDeviceToJoypad)
        {
            uintptr_t offset = StringToAddr(Offsets::JoypadInputOffset);
            if (offset > 0)
            {
                switchInputDeviceToJoypad = (LPVOID)(base + offset);
                if (Config::Get().debug_console)
                    std::cout << "[HookWndProc] Found SwitchInputDeviceToJoypad via offset at: " << switchInputDeviceToJoypad << '\n';
            }
            else
            {
                std::string pattern = XorString::decrypt(EncryptedPatterns::SwitchInputDeviceToJoypad);
                switchInputDeviceToJoypad = Scanner::ScanMainMod(pattern.c_str());
                if (Config::Get().debug_console)
                    std::cout << "[HookWndProc] Found SwitchInputDeviceToJoypad via pattern at: " << switchInputDeviceToJoypad << '\n';
            }
        }
        if (!switchInputDeviceToKeyboard)
        {
            uintptr_t offset = StringToAddr(Offsets::KeyboardMouseInputOffset);
            if (offset > 0)
            {
                switchInputDeviceToKeyboard = (LPVOID)(base + offset);
                if (Config::Get().debug_console)
                    std::cout << "[HookWndProc] Found SwitchInputDeviceToKeyboard via offset at: " << switchInputDeviceToKeyboard << '\n';
            }
            else
            {
                std::string pattern = XorString::decrypt(EncryptedPatterns::SwitchInputDeviceToKeyboard);
                switchInputDeviceToKeyboard = Scanner::ScanMainMod(pattern.c_str());
                if (Config::Get().debug_console)
                    std::cout << "[HookWndProc] Found SwitchInputDeviceToKeyboard via pattern at: " << switchInputDeviceToKeyboard << '\n';
            }
        }
        if (!switchInputDeviceToTouchScreen)
        {
            uintptr_t offset = StringToAddr(Offsets::TouchInputOffset);
            if (offset > 0)
            {
                switchInputDeviceToTouchScreen = (LPVOID)(base + offset);
                if (Config::Get().debug_console)
                    std::cout << "[HookWndProc] Found SwitchInputDeviceToTouchScreen via offset at: " << switchInputDeviceToTouchScreen << '\n';
            }
            else
            {
                std::string pattern = XorString::decrypt(EncryptedPatterns::SwitchInputDeviceToTouchScreen);
                switchInputDeviceToTouchScreen = Scanner::ScanMainMod(pattern.c_str());
            }
        }
    }
    
    HWND hWnd = FindUnityMainWindow();
    if (hWnd)
    {
        SetUnityMainWindow(hWnd);
    }
    else
    {
        if (Config::Get().debug_console)
            std::cout << "[HookWndProc] Unity main window not found during initialization" << '\n';
    }
}

HWND FindUnityMainWindow()
{
    HWND result = nullptr;
    EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&result));
    return result;
}

BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam)
{
    if (!IsWindowVisible(hWnd))
        return TRUE;
    
    wchar_t className[256];
    GetClassNameW(hWnd, className, 256);
    
    std::wstring classNameStr(className);
    if (classNameStr.find(L"UnityWndClass") != std::wstring::npos || 
        classNameStr.find(L"Unity") != std::wstring::npos)
    {
        wchar_t windowTitle[256];
        GetWindowTextW(hWnd, windowTitle, 256);
        if (wcslen(windowTitle) > 0)
        {
            HWND* pResult = reinterpret_cast<HWND*>(lParam);
            *pResult = hWnd;
            return FALSE;
        }
    }
    return TRUE;
}