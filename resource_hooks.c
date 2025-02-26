#include "resource_hooks.h"
#include "resource_monitor.h"
#include "resource_types.h"
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    void* original_addr;
    void* hook_addr;
    bool is_inline;
} HookStatus;

static struct {
    HookStatus createFile;
    HookStatus readFile;
    HookStatus writeFile;
    HookStatus socket;
} g_hook_status = {0};

// Static variables to store original functions
static OriginalFunctions g_original_functions = {0};
static ResourceMonitor* g_monitor = NULL;

// Add debug flag
static bool g_debug_mode = true;

// Add debug print function
static void debug_print(const char* format, ...) {
    if (!g_debug_mode) return;

    va_list args;
    va_start(args, format);
    printf("[DEBUG] ");
    vprintf(format, args);
    printf("\n");
    va_end(args);
}

// Hook function implementations
static HANDLE WINAPI CreateFileW_Hook(
        LPCWSTR lpFileName,
DWORD dwDesiredAccess,
        DWORD dwShareMode,
LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        DWORD dwCreationDisposition,
DWORD dwFlagsAndAttributes,
        HANDLE hTemplateFile
) {
debug_print("CreateFileW called for: %ws", lpFileName);

ActivityRecord* activity = (ActivityRecord*)calloc(1, sizeof(ActivityRecord));
if (activity) {
activity->resource_type = RESOURCE_FILE_SYSTEM;
wcstombs(activity->file.path, lpFileName, MAX_PATH - 1);

// Determine detailed access type
if (dwDesiredAccess & GENERIC_READ) activity->file.access_type |= ACCESS_READ;
if (dwDesiredAccess & GENERIC_WRITE) activity->file.access_type |= ACCESS_WRITE;
if (dwCreationDisposition == CREATE_NEW ||
dwCreationDisposition == CREATE_ALWAYS) {
activity->file.access_type |= ACCESS_CREATE;
}
if (dwDesiredAccess & DELETE) activity->file.access_type |= ACCESS_DELETE;

GetSystemTimeAsFileTime(&activity->file.timestamp);

// Debug print before recording
debug_print("Recording file activity: %s (Access: 0x%x)",
activity->file.path, activity->file.access_type);

monitor_record_activity(g_monitor, activity);
}

return g_original_functions.CreateFileW(
        lpFileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile
);
}

static BOOL WINAPI WriteFile_Hook(
        HANDLE hFile,
        LPCVOID lpBuffer,
        DWORD nNumberOfBytesToWrite,
        LPDWORD lpNumberOfBytesWritten,
        LPOVERLAPPED lpOverlapped
) {
    ActivityRecord* activity = (ActivityRecord*)calloc(1, sizeof(ActivityRecord));
    if (activity) {
        activity->resource_type = RESOURCE_FILE_SYSTEM;
        activity->file.access_type = ACCESS_WRITE;
        activity->file.bytes_transferred = nNumberOfBytesToWrite;

        // Get file name from handle
        char filename[MAX_PATH];
        if (GetFinalPathNameByHandleA(hFile, filename, MAX_PATH, FILE_NAME_NORMALIZED)) {
            strncpy(activity->file.path, filename, MAX_PATH - 1);
        } else {
            strcpy(activity->file.path, "<unknown>");
        }

        GetSystemTimeAsFileTime(&activity->file.timestamp);
        monitor_record_activity(g_monitor, activity);
    }

    return g_original_functions.WriteFile(
            hFile,
            lpBuffer,
            nNumberOfBytesToWrite,
            lpNumberOfBytesWritten,
            lpOverlapped
    );
}

static BOOL WINAPI ReadFile_Hook(
        HANDLE hFile,
        LPVOID lpBuffer,
        DWORD nNumberOfBytesToRead,
        LPDWORD lpNumberOfBytesRead,
        LPOVERLAPPED lpOverlapped
) {
    ActivityRecord* activity = (ActivityRecord*)calloc(1, sizeof(ActivityRecord));
    if (activity) {
        activity->resource_type = RESOURCE_FILE_SYSTEM;
        activity->file.access_type = ACCESS_READ;
        activity->file.bytes_transferred = nNumberOfBytesToRead;

        // Get file name from handle
        char filename[MAX_PATH];
        if (GetFinalPathNameByHandleA(hFile, filename, MAX_PATH, FILE_NAME_NORMALIZED)) {
            strncpy(activity->file.path, filename, MAX_PATH - 1);
        } else {
            strcpy(activity->file.path, "<unknown>");
        }

        GetSystemTimeAsFileTime(&activity->file.timestamp);
        monitor_record_activity(g_monitor, activity);
    }

    return g_original_functions.ReadFile(
            hFile,
            lpBuffer,
            nNumberOfBytesToRead,
            lpNumberOfBytesRead,
            lpOverlapped
    );
}

static SOCKET WINAPI Socket_Hook(
        int af,
        int type,
        int protocol
) {
    ActivityRecord* activity = (ActivityRecord*)calloc(1, sizeof(ActivityRecord));
    if (activity) {
        activity->resource_type = RESOURCE_NETWORK;
        activity->network.access_type = ACCESS_NETWORK_CONNECT;
        GetSystemTimeAsFileTime(&activity->network.timestamp);

        monitor_record_activity(g_monitor, activity);
    }

    return g_original_functions.Socket(af, type, protocol);
}

static int WINAPI Connect_Hook(
        SOCKET s,
        const struct sockaddr* name,
        int namelen
) {
    ActivityRecord* activity = (ActivityRecord*)calloc(1, sizeof(ActivityRecord));
    if (activity) {
        activity->resource_type = RESOURCE_NETWORK;
        activity->network.access_type = ACCESS_NETWORK_CONNECT;

        // Get remote address information
        if (name->sa_family == AF_INET) {
            struct sockaddr_in* addr = (struct sockaddr_in*)name;
            inet_ntop(AF_INET, &(addr->sin_addr),
                      activity->network.remote_address,
                      sizeof(activity->network.remote_address));
            activity->network.remote_port = ntohs(addr->sin_port);
        }
        else if (name->sa_family == AF_INET6) {
            struct sockaddr_in6* addr = (struct sockaddr_in6*)name;
            inet_ntop(AF_INET6, &(addr->sin6_addr),
                      activity->network.remote_address,
                      sizeof(activity->network.remote_address));
            activity->network.remote_port = ntohs(addr->sin6_port);
        }

        GetSystemTimeAsFileTime(&activity->network.timestamp);
        monitor_record_activity(g_monitor, activity);
    }

    return g_original_functions.Connect(s, name, namelen);
}

bool hook_create_inline(void* target_function, void* hook_function, void** original_function) {
    if (!target_function || !hook_function) {
        debug_print("Invalid function pointers for inline hook");
        return false;
    }

    BYTE* target = (BYTE*)target_function;

    // Save original function pointer
    if (original_function) {
        *original_function = target;
    }

    // Create jump instruction
    BYTE jump[] = {
            0x48, 0xB8,                 // movabs rax,
            0x00, 0x00, 0x00, 0x00,    // target address
            0x00, 0x00, 0x00, 0x00,
            0xFF, 0xE0                  // jmp rax
    };

    // Write hook address
    *(void**)(jump + 2) = hook_function;

    // Modify page protection
    DWORD old_protect;
    if (!VirtualProtect(target, sizeof(jump), PAGE_EXECUTE_READWRITE, &old_protect)) {
        debug_print("Failed to modify memory protection for inline hook: %d", GetLastError());
        return false;
    }

    // Write jump instruction
    memcpy(target, jump, sizeof(jump));

    // Restore protection
    VirtualProtect(target, sizeof(jump), old_protect, &old_protect);

    debug_print("Inline hook installed at %p -> %p", target_function, hook_function);
    return true;
}

// Modified hook installation
bool resource_hooks_install(struct ResourceMonitor* monitor, struct HookTable* hook_table) {
    if (!monitor || !hook_table) {
        debug_print("Invalid monitor or hook table");
        return false;
    }

    debug_print("Installing resource hooks...");
    g_monitor = monitor;
    bool success = true;

    // Get module handles
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    HMODULE ws2_32 = GetModuleHandleA("ws2_32.dll");

    if (!kernel32 || !ws2_32) {
        debug_print("Failed to get module handles: kernel32=%p, ws2_32=%p", kernel32, ws2_32);
        return false;
    }

    // Get original function addresses
    void* orig_CreateFile = GetProcAddress(kernel32, "CreateFileW");
    void* orig_ReadFile = GetProcAddress(kernel32, "ReadFile");
    void* orig_WriteFile = GetProcAddress(kernel32, "WriteFile");
    void* orig_Socket = GetProcAddress(ws2_32, "socket");

    if (!orig_CreateFile || !orig_ReadFile || !orig_WriteFile || !orig_Socket) {
        debug_print("Failed to get function addresses");
        return false;
    }

    // Install hooks directly
    debug_print("Installing CreateFileW hook...");
    success &= hook_create_inline(orig_CreateFile, CreateFileW_Hook, &g_original_functions.CreateFileW);
    if (success) {
        g_hook_status.createFile.original_addr = orig_CreateFile;
        g_hook_status.createFile.hook_addr = CreateFileW_Hook;
        g_hook_status.createFile.is_inline = true;
    }

    debug_print("Installing ReadFile hook...");
    success &= hook_create_inline(orig_ReadFile, ReadFile_Hook, &g_original_functions.ReadFile);
    if (success) {
        g_hook_status.readFile.original_addr = orig_ReadFile;
        g_hook_status.readFile.hook_addr = ReadFile_Hook;
        g_hook_status.readFile.is_inline = true;
    }

    debug_print("Installing WriteFile hook...");
    success &= hook_create_inline(orig_WriteFile, WriteFile_Hook, &g_original_functions.WriteFile);
    if (success) {
        g_hook_status.writeFile.original_addr = orig_WriteFile;
        g_hook_status.writeFile.hook_addr = WriteFile_Hook;
        g_hook_status.writeFile.is_inline = true;
    }

    debug_print("Installing Socket hook...");
    success &= hook_create_inline(orig_Socket, Socket_Hook, &g_original_functions.Socket);
    if (success) {
        g_hook_status.socket.original_addr = orig_Socket;
        g_hook_status.socket.hook_addr = Socket_Hook;
        g_hook_status.socket.is_inline = true;
    }

    debug_print("Hook installation %s", success ? "successful" : "failed");
    return success;
}

// Modified verification
bool verify_hooks() {
    debug_print("Verifying hooks...");

    bool all_valid = true;

    // Verify CreateFileW hook
    if (!g_hook_status.createFile.original_addr || !g_hook_status.createFile.hook_addr) {
        debug_print("CreateFileW hook verification failed");
        all_valid = false;
    }

    // Verify ReadFile hook
    if (!g_hook_status.readFile.original_addr || !g_hook_status.readFile.hook_addr) {
        debug_print("ReadFile hook verification failed");
        all_valid = false;
    }

    // Verify WriteFile hook
    if (!g_hook_status.writeFile.original_addr || !g_hook_status.writeFile.hook_addr) {
        debug_print("WriteFile hook verification failed");
        all_valid = false;
    }

    // Verify Socket hook
    if (!g_hook_status.socket.original_addr || !g_hook_status.socket.hook_addr) {
        debug_print("Socket hook verification failed");
        all_valid = false;
    }

    debug_print("Hook verification %s", all_valid ? "successful" : "failed");
    return all_valid;
}

void test_hooks(void) {
    debug_print("Testing hooks...");

    // Test file creation
    HANDLE hFile = CreateFileW(L"test.txt",
                               GENERIC_WRITE | GENERIC_READ,
                               0, NULL,
                               CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL,
                               NULL);

    if (hFile != INVALID_HANDLE_VALUE) {
        // Test write operation
        const char* test_data = "Test data";
        DWORD written;
        WriteFile(hFile, test_data, strlen(test_data), &written, NULL);

        // Test read operation
        char buffer[256];
        DWORD read;
        SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
        ReadFile(hFile, buffer, sizeof(buffer), &read, NULL);

        CloseHandle(hFile);
        DeleteFileW(L"test.txt");
        debug_print("File operations test completed");
    } else {
        debug_print("Failed to create test file: %d", GetLastError());
    }
}

// Add hook test function
void test_file_operation() {
    debug_print("Testing file operations...");

    // Test file creation
    HANDLE hFile = CreateFileW(L"test.txt",
                               GENERIC_WRITE | GENERIC_READ,
                               0, NULL,
                               CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL,
                               NULL);

    if (hFile != INVALID_HANDLE_VALUE) {
        // Test write operation
        const char* test_data = "Test data";
        DWORD written;
        WriteFile(hFile, test_data, strlen(test_data), &written, NULL);

        // Test read operation
        char buffer[256];
        DWORD read;
        SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
        ReadFile(hFile, buffer, sizeof(buffer), &read, NULL);

        CloseHandle(hFile);
        DeleteFileW(L"test.txt");
        debug_print("File operations test completed");
    } else {
        debug_print("Failed to create test file: %d", GetLastError());
    }
}

static BOOL WINAPI CreateProcessW_Hook(
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
) {
    ActivityRecord* activity = (ActivityRecord*)calloc(1, sizeof(ActivityRecord));
    if (activity) {
        activity->resource_type = RESOURCE_PROCESS;
        if (lpApplicationName) {
            wcstombs(activity->process.image_name, lpApplicationName, MAX_PATH);
        } else if (lpCommandLine) {
            wcstombs(activity->process.image_name, lpCommandLine, MAX_PATH);
        }
        activity->process.access_type = ACCESS_CREATE;
        GetSystemTimeAsFileTime(&activity->process.timestamp);

        monitor_record_activity(g_monitor, activity);
    }

    return g_original_functions.CreateProcessW(
            lpApplicationName,
            lpCommandLine,
            lpProcessAttributes,
            lpThreadAttributes,
            bInheritHandles,
            dwCreationFlags,
            lpEnvironment,
            lpCurrentDirectory,
            lpStartupInfo,
            lpProcessInformation
    );
}

// Remove hooks
bool resource_hooks_remove(struct ResourceMonitor* monitor, struct HookTable* hook_table) {
    if (!monitor || !hook_table) return false;

    bool success = true;

    // Remove all installed hooks
    success &= hook_remove(hook_table, HOOK_TARGET_CREATEFILE, MODULE_KERNEL32);
    success &= hook_remove(hook_table, HOOK_TARGET_SOCKET, MODULE_WS2_32);
    success &= hook_remove(hook_table, HOOK_TARGET_PROCESS, MODULE_KERNEL32);

    // Clear monitor reference and original functions
    g_monitor = NULL;
    memset(&g_original_functions, 0, sizeof(g_original_functions));

    return success;
}

// Get original function pointers
const OriginalFunctions* resource_hooks_get_originals(void) {
    return &g_original_functions;
}