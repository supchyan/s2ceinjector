#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <fstream>

inline bool exists(const std::string& name) {
    struct stat buffer;
    return (stat(name.c_str(), &buffer) == 0);
}

void printExitMessage() {
    printf("\nPress ENTER to exit...\n");
    getchar();
}
DWORD getProcessByName(const char* procName)
{
    char _procName[255];

    PROCESSENTRY32 ProcList{};
    ProcList.dwSize = sizeof(ProcList);

    const HANDLE hProcList = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcList == INVALID_HANDLE_VALUE)
        return -1;

    if (!Process32First(hProcList, &ProcList))
        return -1;

    wcstombs_s(nullptr, _procName, ProcList.szExeFile, 255);

    if (lstrcmpA(_procName, procName) == 0)
        return ProcList.th32ProcessID;

    while (Process32Next(hProcList, &ProcList))
    {
        wcstombs_s(nullptr, _procName, ProcList.szExeFile, 255);

        if (lstrcmpA(_procName, procName) == 0)
            return ProcList.th32ProcessID;
    }

    return -1;
}

int main(const int argc, char* argv[])
{
    LPCSTR dllName  = "s2ce.dll";
    LPCSTR procName = "sai2.exe";
    wchar_t wProcName[20];
    mbstowcs(wProcName, procName, strlen(procName) + 1);//Plus null
    LPWSTR lpwProcName = wProcName;
    char fullDLLPath[MAX_PATH];

    STARTUPINFO startInfo = { sizeof(startInfo) };
    PROCESS_INFORMATION procInfo;

    ZeroMemory(&startInfo, sizeof(startInfo));
    startInfo.cb = sizeof(startInfo);
    ZeroMemory(&procInfo, sizeof(procInfo));

    printf("S2CE ver. 2.0\n\n");

    const DWORD fullPathResult = GetFullPathNameA(dllName, MAX_PATH, fullDLLPath, nullptr);
    if (fullPathResult == 0)
    {
        printf("[ERR] Cannot invoke GetFullPathNameA.\n");
        printExitMessage();
        return -1;
    }

    if (!exists(fullDLLPath)) {
        printf("[ERR] Cannot find <%s>. Check if <%s> is in sa2's root directory.\n", dllName, dllName);
        printExitMessage();
        return -1;
    }
        

    if (!CreateProcess(
        NULL,                   // Module name
        lpwProcName,            // Command line
        NULL,                   // Process handle not inheritable
        NULL,                   // Thread handle not inheritable
        TRUE,                   // Handle inheritance
        0,                      // Creation flags
        NULL,                   // Use parent's environment block
        NULL,                   // Use parent's starting directory 
        &startInfo,             // Pointer to STARTUPINFO structure
        &procInfo)              // Pointer to PROCESS_INFORMATION structure
        )
    {
        printf("[ERR] Cannot run <%s>. Check if this executable is in sai2's root directory.\n", procName);
        printExitMessage();
        return -1;
    }

    printf("[OK] %s started\n", procName);

    const DWORD pid = getProcessByName(procName);

    if (pid == (DWORD)-1) {
        return -1;
    }

    printf("[>>] PID: %i\n\n", (int)pid);

    const HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hTargetProcess == INVALID_HANDLE_VALUE)
    {
        printf("[ERR] Cannot handle sai2.exe\n");
        printExitMessage();
        return -1;
    }

    printf("[OK] DLL injected\n");

    const LPVOID pathAddr = VirtualAllocEx(hTargetProcess, nullptr, lstrlenA(fullDLLPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pathAddr == nullptr)
    {
        printf("[ERR] Cannot allocate memory in hProc.\n");
        printExitMessage();
        return -1;
    }

    printf("[OK] Memory allocated at 0x%X\n", (UINT)(uintptr_t)pathAddr);

    const DWORD writeMemRes = WriteProcessMemory(hTargetProcess, pathAddr, fullDLLPath, static_cast<SIZE_T>(lstrlenA(fullDLLPath)) + 1, nullptr);
    if (writeMemRes == 0)
    {
        printf("[ERR] Cannot write DLL path into hProc.\n");
        printExitMessage();
        return -1;
    }

    printf("[OK] DLL path written\n");

    const HMODULE hModule = GetModuleHandleA("kernel32.dll");
    if (hModule == INVALID_HANDLE_VALUE || hModule == nullptr)
        return -1;

    const FARPROC funcAddr = GetProcAddress(hModule, "LoadLibraryA");
    if (funcAddr == nullptr)
    {
        printf("[ERR] Cannot get \"LoadLibraryA\" address.\n");
        printExitMessage();
        return -1;
    }

    printf("[OK] LoadLibraryA address at 0x%X\n", (UINT)(uintptr_t)funcAddr);

    const HANDLE hThreadCreationResult = CreateRemoteThread(hTargetProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)funcAddr, pathAddr, 0, nullptr);
    if (hThreadCreationResult == INVALID_HANDLE_VALUE)
    {
        printf("[ERR] Cannot create the thread in the process.\n");
        printExitMessage();
        return -1;
    }

    printf("[OK] Done\n");

    WaitForSingleObject(procInfo.hProcess, INFINITE);
    CloseHandle(procInfo.hProcess);
    CloseHandle(procInfo.hThread);

    return 0;
}