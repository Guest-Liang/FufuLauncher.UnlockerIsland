#include <windows.h>
#include <shlwapi.h>
#include <iostream>
#include <string>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <vector>

#pragma comment(lib, "shlwapi.lib")

const wchar_t* PLUGINS_SUBDIR_NAME = L"Plugins";

std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

std::wstring GetCurrentExeDirectory() {
    wchar_t modulePath[MAX_PATH];
    if (GetModuleFileNameW(NULL, modulePath, MAX_PATH) > 0) {
        std::wstring path(modulePath);
        size_t lastSlash = path.find_last_of(L"\\/");
        if (lastSlash != std::wstring::npos) {
            return path.substr(0, lastSlash);
        }
    }
    return L".";
}


std::wstring GetLogFilePath() {
    return GetCurrentExeDirectory() + L"\\Launcher.log";
}

void WriteLog(const std::string& message) {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::tm tm; localtime_s(&tm, &time_t);
    std::stringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");

    std::ofstream logFile(GetLogFilePath(), std::ios::app);
    if (logFile.is_open()) {
        logFile << "[" << ss.str() << "] " << message << std::endl;
    }
}

void HideConsole() {
    HWND hwnd = GetConsoleWindow();
    if (hwnd != NULL) ShowWindow(hwnd, SW_HIDE);
}

bool InjectDll(HANDLE hProcess, const std::wstring& dllPath) {
    if (GetFileAttributesW(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) return false;

    std::wstring injectPath = dllPath;
    DWORD shortPathLen = GetShortPathNameW(dllPath.c_str(), nullptr, 0);
    if (shortPathLen > 0) {
        std::vector<wchar_t> shortPath(shortPathLen);
        if (GetShortPathNameW(dllPath.c_str(), shortPath.data(), shortPathLen) > 0) {
            injectPath = shortPath.data();
        }
    }

    size_t size = (injectPath.length() + 1) * sizeof(wchar_t);
    LPVOID remoteMem = VirtualAllocEx(hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) return false;

    if (!WriteProcessMemory(hProcess, remoteMem, injectPath.c_str(), size, nullptr)) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    LPTHREAD_START_ROUTINE loadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, loadLibrary, remoteMem, 0, nullptr);
    if (!hThread) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hThread);

    return exitCode != 0;
}

void RecursiveScanAndInject(HANDLE hProcess, const std::wstring& directory, int& injectedCount) {
    std::wstring searchPath = directory + L"\\*";
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0)
            continue;

        std::wstring fullPath = directory + L"\\" + findData.cFileName;

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            RecursiveScanAndInject(hProcess, fullPath, injectedCount);
        } else {
            size_t nameLen = wcslen(findData.cFileName);
            if (nameLen > 4) {
                const wchar_t* ext = findData.cFileName + nameLen - 4;
                if (_wcsicmp(ext, L".dll") == 0) {
                    std::wstring wFileName = findData.cFileName;
                    std::string sFileName = WStringToString(wFileName);

                    WriteLog("发现插件: " + sFileName + "，正在注入...");

                    if (InjectDll(hProcess, fullPath)) {
                        WriteLog("插件注入成功: " + sFileName);
                        injectedCount++;
                    } else {
                        WriteLog("错误: 插件注入失败: " + sFileName);
                    }
                }
            }
        }
    } while (FindNextFileW(hFind, &findData) != 0);

    FindClose(hFind);
}

void InjectPlugins(HANDLE hProcess) {
    std::wstring exeDir = GetCurrentExeDirectory();
    std::wstring pluginsDir = exeDir + L"\\" + PLUGINS_SUBDIR_NAME;

    if (GetFileAttributesW(pluginsDir.c_str()) == INVALID_FILE_ATTRIBUTES) {
        CreateDirectoryW(pluginsDir.c_str(), NULL);
        WriteLog("创建 Plugins 目录: " + WStringToString(pluginsDir));
    }
    
    std::wstring offsetJsonPath = pluginsDir + L"\\offset.json";
    if (GetFileAttributesW(offsetJsonPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        WriteLog("监测到历史下载文件 offset.json，正在执行移除...");
        if (DeleteFileW(offsetJsonPath.c_str())) {
            WriteLog("历史文件 offset.json 移除成功");
        } else {
            WriteLog("警告: 无法移除 offset.json，错误码: " + std::to_string(GetLastError()));
        }
    }

    WriteLog("正在递归扫描插件目录: " + WStringToString(pluginsDir));

    int totalInjected = 0;
    RecursiveScanAndInject(hProcess, pluginsDir, totalInjected);

    WriteLog("插件加载完成，共注入: " + std::to_string(totalInjected) + " 个插件");
}

int wmain(int argc, wchar_t* argv[]) {
    std::locale::global(std::locale("zh_CN.UTF-8"));
    std::wcout.imbue(std::locale("zh_CN.UTF-8"));

    WriteLog("=== 启动器会话开始 ===");

    if (argc < 2) {
        std::wcerr << L"[-] 错误: 未提供游戏路径启动参数。" << std::endl;
        std::wcerr << L"[-] 用法: Launcher.exe <GamePath>" << std::endl;
        WriteLog("错误: 未提供游戏路径启动参数，程序退出。");
        return 1;
    }

    std::wstring gamePath = argv[1];

    if (!PathFileExistsW(gamePath.c_str())) {
        std::wcerr << L"[-] 错误: 指定的游戏路径不存在: " << gamePath << std::endl;
        WriteLog("错误: 指定的游戏路径不存在: " + WStringToString(gamePath));
        return 1;
    }

    WriteLog("从启动参数获取游戏路径: " + WStringToString(gamePath));

    HideConsole();

    std::wstring workingDir = gamePath.substr(0, gamePath.find_last_of(L"\\/"));
    WriteLog("游戏工作目录: " + WStringToString(workingDir));

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(
        gamePath.c_str(),
        nullptr,
        nullptr,
        nullptr,
        FALSE,
        CREATE_SUSPENDED,
        nullptr,
        workingDir.c_str(),
        &si,
        &pi))
    {
        WriteLog("[-] 无法创建游戏进程，错误代码: " + std::to_string(GetLastError()));
        return 1;
    }

    WriteLog("游戏进程创建成功，开始注入插件...");
    
    InjectPlugins(pi.hProcess);

    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    WriteLog("=== 游戏已启动并完成注入流程 ===");
    return 0;
}