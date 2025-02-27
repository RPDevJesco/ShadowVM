#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <conio.h>
#include "resource_monitor.h"
#include "resource_hooks.h"
#include "container.h"

// Console buffer for activity logging
#define CONSOLE_BUFFER_SIZE 50
#define MAX_LINE_LENGTH 256

// Activity callback function to handle resource access
static bool activity_callback(ResourceMonitor* monitor, const ActivityRecord* activity, void* context) {
    // Format timestamp
    SYSTEMTIME st;
    GetLocalTime(&st);
    char timestamp[32];
    sprintf(timestamp, "[%02d:%02d:%02d.%03d]",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    // Format activity information based on type
    char activity_info[MAX_LINE_LENGTH] = {0};
    SecuritySeverity severity_level = SEVERITY_NORMAL;

    switch (activity->resource_type) {
        case RESOURCE_FILE_SYSTEM:
            snprintf(activity_info, sizeof(activity_info), "%s FILE: %s [%s]",
                     timestamp,
                     activity->file.path,
                     (activity->file.access_type & ACCESS_READ) ? "READ" :
                     (activity->file.access_type & ACCESS_WRITE) ? "WRITE" :
                     (activity->file.access_type & ACCESS_CREATE) ? "CREATE" : "ACCESS");
            break;

        case RESOURCE_NETWORK:
            snprintf(activity_info, sizeof(activity_info), "%s NET: %s:%u [%s]",
                     timestamp,
                     activity->network.remote_address,
                     activity->network.remote_port,
                     (activity->network.access_type & ACCESS_NETWORK_CONNECT) ? "CONNECT" :
                     (activity->network.access_type & ACCESS_NETWORK_LISTEN) ? "LISTEN" : "ACCESS");

            // Increase severity level on network activity
            severity_level = SEVERITY_WARNING;
            break;

        case RESOURCE_PROCESS:
            snprintf(activity_info, sizeof(activity_info), "%s PROC: %s (PID: %u) [%s]",
                     timestamp,
                     activity->process.image_name,
                     activity->process.process_id,
                     (activity->process.access_type & ACCESS_CREATE) ? "CREATE" : "ACCESS");
            break;

        case RESOURCE_REGISTRY:
            snprintf(activity_info, sizeof(activity_info), "%s REG: %s [%s]",
                     timestamp,
                     activity->registry.key_path,
                     (activity->registry.access_type & ACCESS_REGISTRY_QUERY) ? "QUERY" :
                     (activity->registry.access_type & ACCESS_REGISTRY_SET) ? "SET" : "ACCESS");
            break;

        case RESOURCE_MEMORY:
            snprintf(activity_info, sizeof(activity_info), "%s MEM: %p Size: %zu [%s]",
                     timestamp,
                     activity->memory.address,
                     activity->memory.size,
                     (activity->memory.protection & PAGE_EXECUTE_READWRITE) ? "RWX" :
                     (activity->memory.protection & PAGE_EXECUTE_READ) ? "RX" :
                     (activity->memory.protection & PAGE_READWRITE) ? "RW" : "ACCESS");

            // Increase severity on executable memory allocation
            if (activity->memory.protection & PAGE_EXECUTE_READWRITE) {
                severity_level = SEVERITY_ALERT;
            }
            break;

        case RESOURCE_DLL:
            snprintf(activity_info, sizeof(activity_info), "%s DLL: %s [LOAD]",
                     timestamp,
                     activity->dll.dll_path);
            break;
    }

    // Check for security violations
    bool is_violation = DetectSecurityViolation(activity);

    // Set severity level
    ContainerContext* container = (ContainerContext*)context;
    if (container && severity_level > container->status.severity_level) {
        container->status.severity_level = severity_level;
    }

    // Log the activity (could append to a file or update UI)
    printf("%s\n", activity_info);

    // Return true to allow the operation, false to block it
    return !is_violation;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        MessageBox(NULL, "Usage: shadowvm.exe <target_executable> [args...]",
                   "ShadowVM Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    // Initialize Windows Sockets
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        MessageBox(NULL, "Failed to initialize Winsock",
                   "ShadowVM Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    // Configure the monitor
    MonitorConfig config = {
            .enabled_resources = RESOURCE_ALL,
            .log_to_file = TRUE,
            .max_records = 1000,
            .block_suspicious = TRUE
    };
    strcpy(config.log_path, "shadowvm.log");

    // Initialize the resource monitor
    ResourceMonitor* monitor = monitor_init(&config);
    if (!monitor) {
        MessageBox(NULL, "Failed to initialize resource monitor",
                   "ShadowVM Error", MB_OK | MB_ICONERROR);
        WSACleanup();
        return 1;
    }

    // Initialize container window
    HINSTANCE hInstance = GetModuleHandle(NULL);
    if (!InitializeContainer(hInstance)) {
        MessageBox(NULL, "Failed to register container window class",
                   "ShadowVM Error", MB_OK | MB_ICONERROR);
        monitor_cleanup(monitor);
        WSACleanup();
        return 1;
    }

    // Create the container
    ContainerContext* container = CreateContainer(hInstance, monitor);
    if (!container) {
        MessageBox(NULL, "Failed to create container window",
                   "ShadowVM Error", MB_OK | MB_ICONERROR);
        monitor_cleanup(monitor);
        WSACleanup();
        return 1;
    }

    // Set activity callback with container as context
    if (!monitor_set_callback(monitor, activity_callback, container)) {
        MessageBox(NULL, "Failed to set activity callback",
                   "ShadowVM Error", MB_OK | MB_ICONERROR);
        CleanupContainer(container);
        monitor_cleanup(monitor);
        WSACleanup();
        return 1;
    }

    // Install hooks
    if (!monitor_install_hooks(monitor)) {
        MessageBox(NULL, "Failed to install monitoring hooks",
                   "ShadowVM Error", MB_OK | MB_ICONERROR);
        CleanupContainer(container);
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

    // Launch process in container
    if (!LaunchProcessInContainer(container, cmdLine)) {
        MessageBox(NULL, "Failed to launch target application",
                   "ShadowVM Error", MB_OK | MB_ICONERROR);
        CleanupContainer(container);
        monitor_remove_hooks(monitor);
        monitor_cleanup(monitor);
        WSACleanup();
        return 1;
    }

    // Main message loop
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // Cleanup resources
    CleanupContainer(container);
    monitor_remove_hooks(monitor);
    monitor_cleanup(monitor);
    WSACleanup();

    return (int)msg.wParam;
}