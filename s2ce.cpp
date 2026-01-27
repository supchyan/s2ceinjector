#include "helper.h"

LPCSTR dll_name  = "s2ce.dll"; // dll to be injected
LPCSTR proc_name = "sai2.exe"; // process to inject to

STARTUPINFO         start_info  { 0 };
PROCESS_INFORMATION proc_info   { 0 };

int main()
{
    // convert LPCSTR to LPWSTR
    wchar_t w_name[16] { 0 };
    mbstowcs(w_name, proc_name, strlen(proc_name) + 1);
    LPWSTR lpw_name = w_name;

    char full_dll_path[MAX_PATH] { 0 };

    ZeroMemory(&proc_info,  sizeof(proc_info) );
    ZeroMemory(&start_info, sizeof(start_info));

    start_info.cb = sizeof(start_info);

    printf("S2CE CLI\n\n");

    const DWORD full_dll_path_result = GetFullPathNameA(dll_name, MAX_PATH, full_dll_path, nullptr);

    if (full_dll_path_result == 0) { // shouldn't be invoked, but ok
        printf("[E] cannot get full <%s> path\n", dll_name);
        print_exit_msg();
        return 0;
    }

    if (!exists(full_dll_path)) { // handle if cannot find `s2ce.dll`
        printf("[E] cannot find <%s>\n", dll_name);
        print_exit_msg();
        return 0;
    }

    if (!CreateProcessW(NULL, lpw_name, NULL, NULL, 1, 0, NULL, NULL, &start_info, &proc_info)) { // handle if cannot run `sai2.exe`
        printf("[E] cannot run <%s>. Does file exist?\n", proc_name);
        print_exit_msg();
        return 0;
    }

    printf("[0] <%s> started\n", proc_name); 

    const DWORD pid = get_pid_by_name(proc_name);

    if (pid == (DWORD)-1) { // proc isn't runnning
        return 0;
    }

    printf("[0] pid: %i\n\n", (int)pid);

    const HANDLE h_target_proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (h_target_proc == INVALID_HANDLE_VALUE) {
        printf("[E] cannot handle <%s>\n", proc_name);
        print_exit_msg();
        return 0;
    }

    const LPVOID path_addr = VirtualAllocEx(h_target_proc, nullptr, lstrlenA(full_dll_path) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (path_addr == nullptr) {
        printf("[E] cannot allocate memory for dll path\n");
        print_exit_msg();
        return 0;
    }

    printf("[0] dll path address: 0x%X\n", (UINT)(uintptr_t)path_addr);

    const DWORD wm_result = WriteProcessMemory(h_target_proc, path_addr, full_dll_path, static_cast<SIZE_T>(lstrlenA(full_dll_path)) + 1, nullptr);
    if (wm_result == 0) {
        printf("[E] cannot write dll path into a process\n");
        print_exit_msg();
        return 0;
    }

    printf("[0] dll injected\n");

    const HMODULE h_module = GetModuleHandleA("kernel32.dll");
    if (h_module == INVALID_HANDLE_VALUE || h_module == nullptr) {
        return 0;
    }

    const FARPROC func_addr = GetProcAddress(h_module, "LoadLibraryA");
    if (func_addr == nullptr) {
        printf("[E] cannot get \"LoadLibraryA\" address\n");
        print_exit_msg();
        return 0;
    }

    printf("[0] \"LoadLibraryA\" address: 0x%X\n", (UINT)(uintptr_t)func_addr);

    const HANDLE hThreadCreationResult = CreateRemoteThread(h_target_proc, nullptr, 0, (LPTHREAD_START_ROUTINE)func_addr, path_addr, 0, nullptr);
    if (hThreadCreationResult == INVALID_HANDLE_VALUE) {
        printf("[E] cannot create remote thread\n");
        print_exit_msg();
        return 0;
    }

    printf("[0] injection separated into a remote thread\n");

    // wait 1 ms to let a proc open
    WaitForSingleObject(proc_info.hProcess, 1);

    // close handlers
    CloseHandle(proc_info.hProcess);
    CloseHandle(proc_info.hThread);

    return 0;
}