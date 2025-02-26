#ifndef RESOURCE_HOOKS_H
#define RESOURCE_HOOKS_H

// Windows headers must be included in this specific order
#define WIN32_LEAN_AND_MEAN  // Exclude rarely-used stuff from Windows headers
#include <winsock2.h>        // Must come before windows.h
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

// Our includes - after all Windows headers
#include "security_types.h"
#include "resource_types.h"
#include "hook_system.h"

// Link with required libraries
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

// Function prototypes for original functions
typedef HANDLE(WINAPI* CreateFile_Fn)(
        LPCWSTR lpFileName,
        DWORD dwDesiredAccess,
        DWORD dwShareMode,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        DWORD dwCreationDisposition,
        DWORD dwFlagsAndAttributes,
        HANDLE hTemplateFile
);

typedef BOOL(WINAPI* WriteFile_Fn)(
        HANDLE hFile,
        LPCVOID lpBuffer,
        DWORD nNumberOfBytesToWrite,
        LPDWORD lpNumberOfBytesWritten,
        LPOVERLAPPED lpOverlapped
);

typedef BOOL(WINAPI* ReadFile_Fn)(
        HANDLE hFile,
        LPVOID lpBuffer,
        DWORD nNumberOfBytesToWrite,
        LPDWORD lpNumberOfBytesWritten,
        LPOVERLAPPED lpOverlapped
);

typedef SOCKET(WINAPI* Socket_Fn)(
        int af,
        int type,
        int protocol
);

typedef int (WINAPI* Connect_Fn)(
        SOCKET s,
        const struct sockaddr* name,
        int namelen
);

typedef BOOL(WINAPI* CreateProcess_Fn)(
        LPCWSTR lpApplicationName,
        LPWSTR lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL bInheritHandles,
        DWORD dwCreationFlags,
        LPVOID lpEnvironment,
        LPCWSTR lpCurrentDirectory,
        LPSTARTUPINFOW lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation
);

typedef LONG(WINAPI* RegOpenKey_Fn)(
        HKEY hKey,
        LPCWSTR lpSubKey,
        DWORD ulOptions,
        REGSAM samDesired,
        PHKEY phkResult
);

typedef LPVOID(WINAPI* VirtualAlloc_Fn)(
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD flAllocationType,
        DWORD flProtect
);

// Structure to hold original functions
typedef struct {
    CreateFile_Fn CreateFileW;
    WriteFile_Fn WriteFile;
    ReadFile_Fn ReadFile;
    Socket_Fn Socket;
    Connect_Fn Connect;
    CreateProcess_Fn CreateProcessW;
    RegOpenKey_Fn RegOpenKeyExW;
    VirtualAlloc_Fn VirtualAlloc;
} OriginalFunctions;

// Hook target definitions
#define HOOK_TARGET_CREATEFILE   "CreateFileW"
#define HOOK_TARGET_WRITEFILE    "WriteFile"
#define HOOK_TARGET_READFILE     "ReadFile"
#define HOOK_TARGET_SOCKET       "socket"
#define HOOK_TARGET_CONNECT      "connect"
#define HOOK_TARGET_PROCESS      "CreateProcessW"
#define HOOK_TARGET_REGISTRY     "RegOpenKeyExW"
#define HOOK_TARGET_VALLOC       "VirtualAlloc"

// Module definitions
#define MODULE_KERNEL32    "kernel32.dll"
#define MODULE_WS2_32      "ws2_32.dll"
#define MODULE_ADVAPI32    "advapi32.dll"

// Function declarations
bool resource_hooks_install(struct ResourceMonitor* monitor, struct HookTable* hook_table);
bool resource_hooks_remove(struct ResourceMonitor* monitor, struct HookTable* hook_table);

const OriginalFunctions* resource_hooks_get_originals(void);
bool verify_hooks();
void test_hooks(void);
#endif // RESOURCE_HOOKS_H