#include <windows.h>
#include <shlwapi.h>
#include <winhttp.h>
#include <string>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <vector>
#include "Launcher.h"

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "winhttp.lib")

const wchar_t* PLUGINS_SUBDIR_NAME = L"Plugins"; 

std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

std::wstring GetCurrentDllDirectory() {
    HMODULE hModule = NULL;
    GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCWSTR)&GetCurrentDllDirectory, 
        &hModule);
    
    if (hModule != NULL) {
        wchar_t modulePath[MAX_PATH];
        if (GetModuleFileNameW(hModule, modulePath, MAX_PATH) > 0) {
            std::wstring path(modulePath);
            size_t lastSlash = path.find_last_of(L"\\/");
            if (lastSlash != std::wstring::npos) {
                return path.substr(0, lastSlash);
            }
        }
    }
    return L".";
}

std::wstring GetLogFilePath() {
    std::wstring dllDir = GetCurrentDllDirectory();
    return dllDir + L"\\Launcher.log";
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

void DownloadOffsetJson(const std::wstring& pluginsDir) {
    WriteLog("尝试连接服务器获取 offset.json...");
    HINTERNET hSession = WinHttpOpen(L"LauncherHTTP/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        WriteLog("系统组件初始化失败，跳过下载步骤。");
        return;
    }

    WinHttpSetTimeouts(hSession, 5000, 5000, 5000, 5000);

    HINTERNET hConnect = WinHttpConnect(hSession, L"154.44.25.230", INTERNET_DEFAULT_HTTP_PORT, 0);
    if (hConnect) {
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/offset.json", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        if (hRequest) {
            if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
                if (WinHttpReceiveResponse(hRequest, NULL)) {
                    DWORD dwStatusCode = 0;
                    DWORD dwSize = sizeof(dwStatusCode);
                    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);
                    
                    if (dwStatusCode == 200) {
                        std::wstring savePath = pluginsDir + L"\\offset.json";
                        std::ofstream outFile(savePath, std::ios::binary);
                        if (outFile.is_open()) {
                            DWORD size = 0;
                            DWORD downloaded = 0;
                            do {
                                size = 0;
                                if (!WinHttpQueryDataAvailable(hRequest, &size)) break;
                                if (size == 0) break;
                                std::vector<char> buffer(size);
                                if (WinHttpReadData(hRequest, (LPVOID)buffer.data(), size, &downloaded)) {
                                    outFile.write(buffer.data(), downloaded);
                                }
                            } while (size > 0);
                            outFile.close();
                            WriteLog("offset.json下载成功并保存至Plugins目录");
                        } else {
                            WriteLog("无法写入offset.json，跳过保存");
                        }
                    } else {
                        WriteLog("服务器响应异常状态码，跳过下载");
                    }
                } else {
                    WriteLog("服务器无响应或连接超时，跳过下载");
                }
            } else {
                WriteLog("连接服务器失败，跳过下载");
            }
            WinHttpCloseHandle(hRequest);
        }
        WinHttpCloseHandle(hConnect);
    }
    WinHttpCloseHandle(hSession);
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
    std::wstring dllDir = GetCurrentDllDirectory();
    std::wstring pluginsDir = dllDir + L"\\" + PLUGINS_SUBDIR_NAME;

    if (GetFileAttributesW(pluginsDir.c_str()) == INVALID_FILE_ATTRIBUTES) {
        CreateDirectoryW(pluginsDir.c_str(), NULL);
        WriteLog("创建 Plugins 目录: " + WStringToString(pluginsDir));
    }

    DownloadOffsetJson(pluginsDir);

    WriteLog("正在递归扫描插件目录: " + WStringToString(pluginsDir));
    
    int totalInjected = 0;
    RecursiveScanAndInject(hProcess, pluginsDir, totalInjected);

    WriteLog("插件加载完成，共注入: " + std::to_string(totalInjected) + " 个插件");
}

extern "C" {
    
    LAUNCHER_API int LaunchGameAndInject(const wchar_t* gamePath, const wchar_t* dllPath, const wchar_t* commandLineArgs, wchar_t* errorMessage, int errorMessageSize) {
        WriteLog("=== 启动会话开始 ===");
        HideConsole();
        
        if (!ValidateGamePath(gamePath)) {
            if (errorMessage) wcsncpy_s(errorMessage, errorMessageSize, L"游戏路径无效", _TRUNCATE);
            WriteLog("错误: 游戏路径无效");
            return 1;
        }

        std::wstring wGamePath = gamePath;
        std::wstring workingDir = wGamePath.substr(0, wGamePath.find_last_of(L"\\/"));

        std::wstring cmdArgs = commandLineArgs ? commandLineArgs : L"";
        wchar_t* pCmdLine = nullptr;
        if (!cmdArgs.empty()) {
            pCmdLine = new wchar_t[cmdArgs.size() + 1];
            wcscpy_s(pCmdLine, cmdArgs.size() + 1, cmdArgs.c_str());
        }

        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};
        
        if (!CreateProcessW(gamePath, pCmdLine, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, workingDir.c_str(), &si, &pi)) {
            if (errorMessage) wcsncpy_s(errorMessage, errorMessageSize, L"创建进程失败", _TRUNCATE);
            WriteLog("错误: CreateProcessW 失败 " + std::to_string(GetLastError()));
            if (pCmdLine) delete[] pCmdLine;
            return 3;
        }

        InjectPlugins(pi.hProcess);
        
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        if (pCmdLine) delete[] pCmdLine;
        
        WriteLog("=== 启动会话完成 ===");
        return 0;
    }

    LAUNCHER_API int GetDefaultDllPath(wchar_t* dllPath, int dllPathSize) {
        if (dllPath && dllPathSize > 0) {
            dllPath[0] = L'\0';
        }
        return 0;
    }

    LAUNCHER_API bool ValidateGamePath(const wchar_t* gamePath) {
        return gamePath && PathFileExistsW(gamePath);
    }

    LAUNCHER_API bool ValidateDllPath(const wchar_t* dllPath) {
        return dllPath && PathFileExistsW(dllPath);
    }
}