#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <conio.h>
#include "resource_monitor.h"
#include "resource_hooks.h"

#define CONSOLE_BUFFER_SIZE 50
#define MAX_LINE_LENGTH 256
// Add to the top of main.c
#define DISPLAY_UPDATE_INTERVAL 550  // Update every 250ms

// Console buffer structure
typedef struct {
    char lines[CONSOLE_BUFFER_SIZE][MAX_LINE_LENGTH];
    int current;
    int count;
    DWORD last_update;  // Track last update time
} ConsoleBuffer;

// Global console buffer
static ConsoleBuffer g_console_buffer = { 0 };
static CRITICAL_SECTION g_console_lock;

void add_console_line(const char* line) {
    if (!line) return;

    EnterCriticalSection(&g_console_lock);

    // Get current time for rate limiting
    DWORD current_time = GetTickCount();

    // Only add new line if enough time has passed (prevents buffer flooding)
    if (current_time - g_console_buffer.last_update > 50) { // 50ms minimum between updates
        // Copy line with overflow protection
        strncpy(g_console_buffer.lines[g_console_buffer.current], line, MAX_LINE_LENGTH - 1);
        g_console_buffer.lines[g_console_buffer.current][MAX_LINE_LENGTH - 1] = '\0';

        // Remove any trailing newlines or carriage returns
        size_t len = strlen(g_console_buffer.lines[g_console_buffer.current]);
        while (len > 0 && (g_console_buffer.lines[g_console_buffer.current][len - 1] == '\n' ||
                           g_console_buffer.lines[g_console_buffer.current][len - 1] == '\r')) {
            g_console_buffer.lines[g_console_buffer.current][--len] = '\0';
        }

        // Update buffer position
        g_console_buffer.current = (g_console_buffer.current + 1) % CONSOLE_BUFFER_SIZE;
        if (g_console_buffer.count < CONSOLE_BUFFER_SIZE) {
            g_console_buffer.count++;
        }

        g_console_buffer.last_update = current_time;
    }

    LeaveCriticalSection(&g_console_lock);
}

// Helper function to clear the console buffer
void clear_console_buffer() {
    EnterCriticalSection(&g_console_lock);

    memset(&g_console_buffer, 0, sizeof(ConsoleBuffer));
    g_console_buffer.last_update = GetTickCount();

    LeaveCriticalSection(&g_console_lock);
}

// Helper function to get a specific line from the buffer
const char* get_console_line(int index) {
    if (index < 0 || index >= g_console_buffer.count) {
        return NULL;
    }

    int actual_index = (g_console_buffer.current - g_console_buffer.count + index + CONSOLE_BUFFER_SIZE)
                       % CONSOLE_BUFFER_SIZE;
    return g_console_buffer.lines[actual_index];
}

static bool activity_callback(ResourceMonitor* monitor, const ActivityRecord* activity, void* context) {
    char line[MAX_LINE_LENGTH];
    SYSTEMTIME st;
    GetLocalTime(&st);

    // Format timestamp
    char timestamp[32];
    sprintf(timestamp, "[%02d:%02d:%02d.%03d]",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    // Format activity details based on type with more information
    switch (activity->resource_type) {
        case RESOURCE_FILE_SYSTEM:
            snprintf(line, sizeof(line), "%s FILE: %s [%s]",
                     timestamp,
                     activity->file.path,
                     (activity->file.access_type & ACCESS_READ) ? "READ" :
                     (activity->file.access_type & ACCESS_WRITE) ? "WRITE" :
                     (activity->file.access_type & ACCESS_CREATE) ? "CREATE" : "ACCESS");
            break;

        case RESOURCE_NETWORK:
            snprintf(line, sizeof(line), "%s NET: %s:%u [%s]",
                     timestamp,
                     activity->network.remote_address,
                     activity->network.remote_port,
                     (activity->network.access_type & ACCESS_NETWORK_CONNECT) ? "CONNECT" :
                     (activity->network.access_type & ACCESS_NETWORK_LISTEN) ? "LISTEN" : "ACCESS");
            break;

        case RESOURCE_PROCESS:
            snprintf(line, sizeof(line), "%s PROC: %s (PID: %u) [%s]",
                     timestamp,
                     activity->process.image_name,
                     activity->process.process_id,
                     (activity->process.access_type & ACCESS_CREATE) ? "CREATE" : "ACCESS");
            break;

        case RESOURCE_REGISTRY:
            snprintf(line, sizeof(line), "%s REG: %s [%s]",
                     timestamp,
                     activity->registry.key_path,
                     (activity->registry.access_type & ACCESS_REGISTRY_QUERY) ? "QUERY" :
                     (activity->registry.access_type & ACCESS_REGISTRY_SET) ? "SET" : "ACCESS");
            break;

        case RESOURCE_MEMORY:
            snprintf(line, sizeof(line), "%s MEM: %p Size: %zu [%s]",
                     timestamp,
                     activity->memory.address,
                     activity->memory.size,
                     (activity->memory.protection & PAGE_EXECUTE_READWRITE) ? "RWX" :
                     (activity->memory.protection & PAGE_EXECUTE_READ) ? "RX" :
                     (activity->memory.protection & PAGE_READWRITE) ? "RW" : "ACCESS");
            break;

        case RESOURCE_DLL:
            snprintf(line, sizeof(line), "%s DLL: %s [LOAD]",
                     timestamp,
                     activity->dll.dll_path);
            break;
    }

    printf("%s\n", line);  // Immediate console output
    add_console_line(line);
    return true;
}

// Initialize console with larger buffer
void init_console_buffer() {
    InitializeCriticalSection(&g_console_lock);
    g_console_buffer.current = 0;
    g_console_buffer.count = 0;

    // Set console buffer size
    HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(console, &csbi);

    COORD new_size;
    new_size.X = csbi.dwSize.X;
    new_size.Y = 5000;  // Larger buffer for scrolling
    SetConsoleScreenBufferSize(console, new_size);
}

void update_console_display(ResourceMonitor* monitor) {
    static DWORD last_update = 0;
    DWORD current_time = GetTickCount();

    // Only update if enough time has passed
    if (current_time - last_update < DISPLAY_UPDATE_INTERVAL) {
        return;
    }
    last_update = current_time;

    // Store console info
    HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(console, &csbi);

    // Clear screen once
    COORD origin = {0, 0};
    DWORD written;
    FillConsoleOutputCharacter(console, ' ',
                               csbi.dwSize.X * csbi.dwSize.Y, origin, &written);
    FillConsoleOutputAttribute(console, csbi.wAttributes,
                               csbi.dwSize.X * csbi.dwSize.Y, origin, &written);
    SetConsoleCursorPosition(console, origin);

    // Print header
    printf("=== ShadowVM Monitor === (Press 'Q' to stop)\n");
    printf("Monitoring PID: %lu | Refresh: 250ms\n", GetCurrentProcessId());
    printf("------------------------------------------------\n\n");

    // Print statistics
    printf("Activity Counts:\n");
    printf("  Files    : %llu (%llu blocked)\n",
           monitor->stats.total_file_ops,
           monitor->stats.total_blocked_ops);
    printf("  Network  : %llu\n", monitor->stats.total_network_ops);
    printf("  Memory   : %llu\n", monitor->stats.total_memory_ops);
    printf("  Registry : %llu\n", monitor->stats.total_registry_ops);
    printf("  Process  : %llu\n", monitor->stats.total_process_ops);
    printf("\n");

    // Print recent activities
    printf("Recent Activities:\n");
    printf("------------------------------------------------\n");

    EnterCriticalSection(&g_console_lock);

    // Show the most recent activities first
    int displayed = 0;
    int max_display = 100;  // Show only last 15 activities
    for (int i = g_console_buffer.count - 1; i >= 0 && displayed < max_display; i--) {
        int idx = (g_console_buffer.current - i - 1 + CONSOLE_BUFFER_SIZE) % CONSOLE_BUFFER_SIZE;
        if (strlen(g_console_buffer.lines[idx]) > 0) {
            printf("%s\n", g_console_buffer.lines[idx]);
            displayed++;
        }
    }

    LeaveCriticalSection(&g_console_lock);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <target_executable> [args...]\n", argv[0]);
        return 1;
    }

    // Initialize Windows Sockets
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        printf("Failed to initialize Winsock: %d\n", GetLastError());
        return 1;
    }

    // Initialize console buffer
    init_console_buffer();

    // Configure the monitor
    MonitorConfig config = {
            .enabled_resources = RESOURCE_ALL,
            .log_to_file = true,
            .max_records = 1000,
            .block_suspicious = true
    };
    strcpy(config.log_path, "monitor.log");

    // Initialize the monitor
    printf("Initializing resource monitor...\n");
    ResourceMonitor* monitor = monitor_init(&config);
    if (!monitor) {
        printf("Failed to initialize resource monitor\n");
        WSACleanup();
        return 1;
    }

    // Set activity callback
    printf("Setting up activity callback...\n");
    if (!monitor_set_callback(monitor, activity_callback, NULL)) {
        monitor_cleanup(monitor);
        WSACleanup();
        return 1;
    }

    // Install hooks
    printf("Installing hooks...\n");
    if (!monitor_install_hooks(monitor)) {
        monitor_cleanup(monitor);
        WSACleanup();
        return 1;
    }

    // Prepare command line for target application
    char cmdLine[MAX_PATH * 2] = {0};
    snprintf(cmdLine, sizeof(cmdLine), "\"%s\"", argv[1]);
    for (int i = 2; i < argc; i++) {
        strncat(cmdLine, " ", sizeof(cmdLine) - strlen(cmdLine) - 1);
        strncat(cmdLine, argv[i], sizeof(cmdLine) - strlen(cmdLine) - 1);
    }

    // Test hooks after installation
    printf("Testing hooks...\n");
    //test_hooks();

    // Create process with proper handle inheritance
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    snprintf(cmdLine, sizeof(cmdLine), "\"%s\"", argv[1]);

    printf("Launching target application: %s\n", cmdLine);
    if (!CreateProcess(NULL, cmdLine, NULL, NULL, TRUE,  // Note: TRUE for handle inheritance
                       CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
                       NULL, NULL, &si, &pi)) {
        printf("Failed to launch target application: %d\n", GetLastError());
        monitor_remove_hooks(monitor);
        monitor_cleanup(monitor);
        WSACleanup();
        return 1;
    }

    // Resume the process
    ResumeThread(pi.hThread);
    printf("Target process resumed (PID: %lu)\n", pi.dwProcessId);

    printf("Launching target application: %s\n", cmdLine);
    if (!CreateProcess(NULL, cmdLine, NULL, NULL, FALSE,
                       CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        printf("Failed to launch target application: %d\n", GetLastError());
        monitor_remove_hooks(monitor);
        monitor_cleanup(monitor);
        WSACleanup();
        return 1;
    }

    // Hide cursor for cleaner display
    HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_CURSOR_INFO cursor_info;
    GetConsoleCursorInfo(console, &cursor_info);
    cursor_info.bVisible = FALSE;
    SetConsoleCursorInfo(console, &cursor_info);

    printf("Monitoring process (PID: %lu). Press 'Q' to stop...\n", pi.dwProcessId);

    // Main monitoring loop
    bool running = true;
    while (running) {
        if (_kbhit()) {
            int key = _getch();
            if (key == 'q' || key == 'Q') {
                running = false;
            }
        }

// Check if target process has ended
        DWORD exit_code;
        if (GetExitCodeProcess(pi.hProcess, &exit_code)) {
            if (exit_code != STILL_ACTIVE) {
                printf("\nTarget application has terminated (Exit code: %lu)\n", exit_code);
                running = false;
            }
        }

// Update display
        update_console_display(monitor);

// Reduced sleep time since we have rate limiting in display update
        Sleep(50);
    }

    // Cleanup
    printf("\nStopping monitor...\n");

    // Terminate process if it's still running
    TerminateProcess(pi.hProcess, 1);

    // Close process handles
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // Restore cursor
    cursor_info.bVisible = TRUE;
    SetConsoleCursorInfo(console, &cursor_info);

    // Remove hooks and cleanup
    monitor_remove_hooks(monitor);
    monitor_cleanup(monitor);
    WSACleanup();
    DeleteCriticalSection(&g_console_lock);

    printf("Monitoring stopped.\n");
    return 0;
}