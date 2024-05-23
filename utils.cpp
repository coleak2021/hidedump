#include "utils.h"
#include <stdio.h>
#include <Windows.h>
unsigned char* encrypt(void* buffer, long long size) {
    unsigned char* new_buff = (unsigned char*)malloc(size);
    SecureZeroMemory(new_buff, size);
    for (long long i = 0; i < size; ++i) {
        new_buff[i] = *(((unsigned char*)buffer) + i) ^ 0x6b;
    }
    return new_buff;
}
bool IsElevated() {
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION Elevation = { 0 };
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
            fRet = Elevation.TokenIsElevated;
        }
    }
    if (hToken) {
        CloseHandle(hToken);
    }
    return fRet;
}
bool SetDebugPrivilege() {
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES TokenPrivileges = { 0 };

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        return FALSE;
    }
    TokenPrivileges.PrivilegeCount = 1;
    TokenPrivileges.Privileges[0].Attributes = TRUE ? SE_PRIVILEGE_ENABLED : 0;
    const wchar_t* lpwPriv = L"SeDebugPrivilege";
    if (!LookupPrivilegeValueW(NULL, (LPCWSTR)lpwPriv, &TokenPrivileges.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return FALSE;
    }
    if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(hToken);
        return FALSE;
    }
    CloseHandle(hToken);
    return TRUE;
}
