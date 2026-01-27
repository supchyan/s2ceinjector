#include <Windows.h>
#include <TlHelp32.h>
#include <fstream>
#pragma once

/**
Returns `true` whenever file exists by `name` specified.
*/
inline bool exists(const std::string& name) {
    struct stat buffer;
    return (stat(name.c_str(), &buffer) == 0);
}

/**
Prints exit message to terminal.
*/
void print_exit_msg() {
    printf("\nPress ENTER to exit...\n");
    int c = getchar();
}

DWORD get_pid_by_name(const char* name)
{
    char _name[255] { 0 };

    PROCESSENTRY32 ProcList { };

    ProcList.dwSize = sizeof(ProcList);

    const HANDLE hProcList = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hProcList == INVALID_HANDLE_VALUE) {
        return -1;
    }

    if (!Process32First(hProcList, &ProcList)) {
        return -1;
    }

    while (Process32Next(hProcList, &ProcList))
    {
        wcstombs_s(nullptr, _name, ProcList.szExeFile, 255);

        if (lstrcmpA(_name, name) == 0) {
            return ProcList.th32ProcessID;
        }
    }

    return -1;
}
