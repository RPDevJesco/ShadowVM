#include "resource_monitor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <psapi.h>
#include <tlhelp32.h>

// Private function declarations
static void log_activity(ResourceMonitor* monitor, const ActivityRecord* activity);
static bool is_suspicious_activity(const ActivityRecord* activity);
static void trim_old_records(ResourceMonitor* monitor);
static ActivityCallback g_activity_callback = NULL;
static void* g_callback_context = NULL;

ResourceMonitor* monitor_init(const MonitorConfig* config) {
    if (!config) {
        printf("Invalid monitor configuration\n");
        return NULL;
    }

    ResourceMonitor* monitor = (ResourceMonitor*)calloc(1, sizeof(ResourceMonitor));
    if (!monitor) {
        printf("Failed to allocate monitor memory\n");
        return NULL;
    }

    // Initialize critical section with error checking
    if (!InitializeCriticalSectionAndSpinCount(&monitor->lock, 0x400)) {
        printf("Failed to initialize critical section: %d\n", GetLastError());
        free(monitor);
        return NULL;
    }

    // Copy configuration
    memcpy(&monitor->config, config, sizeof(MonitorConfig));

    // Initialize hook table with error checking
    printf("Initializing hook table...\n");
    monitor->hook_table = hook_init(32);
    if (!monitor->hook_table) {
        printf("Failed to initialize hook table: %d\n", GetLastError());
        DeleteCriticalSection(&monitor->lock);
        free(monitor);
        return NULL;
    }

    // Verify log file can be created if logging is enabled
    if (config->log_to_file) {
        FILE* test_file = fopen(config->log_path, "w");
        if (!test_file) {
            printf("Failed to create log file '%s': %d\n",
                   config->log_path, GetLastError());
            hook_cleanup(monitor->hook_table);
            DeleteCriticalSection(&monitor->lock);
            free(monitor);
            return NULL;
        }
        fclose(test_file);
    }

    return monitor;
}

bool monitor_install_hooks(ResourceMonitor* monitor) {
    if (!monitor) {
        printf("Invalid monitor parameter\n");
        return false;
    }

    // Verify hook table exists
    if (!monitor->hook_table) {
        printf("Hook table not initialized\n");
        return false;
    }

    // Verify required DLLs are available
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    if (!kernel32) {
        printf("Failed to get handle for kernel32.dll: %d\n", GetLastError());
        return false;
    }

    HMODULE ws2_32 = GetModuleHandleA("ws2_32.dll");
    if (!ws2_32) {
        printf("Failed to get handle for ws2_32.dll: %d\n", GetLastError());
        return false;
    }

    printf("Installing resource hooks...\n");
    bool success = resource_hooks_install(monitor, monitor->hook_table);
    if (!success) {
        printf("Failed to install resource hooks: %d\n", GetLastError());
        return false;
    }

    return true;
}

// Record new activity
bool monitor_record_activity(ResourceMonitor* monitor, ActivityRecord* activity) {
    if (!monitor || !activity) return false;

    // Check if resource type is enabled
    if (!(monitor->config.enabled_resources & activity->resource_type)) {
        return false;
    }

    // Check for suspicious activity
    if (monitor->config.block_suspicious && is_suspicious_activity(activity)) {
        monitor->stats.total_blocked_ops++;
        return false;
    }

    // Call callback if registered
    if (g_activity_callback) {
        if (!g_activity_callback(monitor, activity, g_callback_context)) {
            monitor->stats.total_blocked_ops++;
            return false;
        }
    }

    EnterCriticalSection(&monitor->lock);

    // Add to activity list
    activity->next = monitor->activities;
    monitor->activities = activity;
    monitor->record_count++;

    // Update statistics
    switch (activity->resource_type) {
        case RESOURCE_FILE_SYSTEM:
            monitor->stats.total_file_ops++;
            break;
        case RESOURCE_NETWORK:
            monitor->stats.total_network_ops++;
            break;
        case RESOURCE_MEMORY:
            monitor->stats.total_memory_ops++;
            break;
        case RESOURCE_REGISTRY:
            monitor->stats.total_registry_ops++;
            break;
        case RESOURCE_PROCESS:
        case RESOURCE_THREAD:
            monitor->stats.total_process_ops++;
            break;
    }

    // Log activity
    if (monitor->config.log_to_file) {
        log_activity(monitor, activity);
    }

    // Trim old records if needed
    if (monitor->record_count > monitor->config.max_records) {
        trim_old_records(monitor);
    }

    LeaveCriticalSection(&monitor->lock);

    return true;
}

// Add a hook status query function:
bool monitor_are_hooks_installed(ResourceMonitor* monitor) {
    if (!monitor) return false;
    return (monitor->hook_table != NULL);
}

// Add a hook enable/disable function:
bool monitor_set_hooks_enabled(ResourceMonitor* monitor, bool enable) {
    if (!monitor || !monitor->hook_table) return false;

    if (enable && !monitor_are_hooks_installed(monitor)) {
        return monitor_install_hooks(monitor);
    }
    else if (!enable && monitor_are_hooks_installed(monitor)) {
        return monitor_remove_hooks(monitor);
    }

    return true;  // Already in desired state
}

// Get activities of specific type
ActivityRecord* monitor_get_activities(ResourceMonitor* monitor, ResourceType type) {
    if (!monitor) return NULL;

    ActivityRecord* filtered = NULL;
    ActivityRecord* current = monitor->activities;

    EnterCriticalSection(&monitor->lock);

    while (current) {
        if (current->resource_type == type) {
            ActivityRecord* copy = (ActivityRecord*)malloc(sizeof(ActivityRecord));
            if (copy) {
                memcpy(copy, current, sizeof(ActivityRecord));
                copy->next = filtered;
                filtered = copy;
            }
        }
        current = current->next;
    }

    LeaveCriticalSection(&monitor->lock);

    return filtered;
}

// Set activity callback
bool monitor_set_callback(ResourceMonitor* monitor, ActivityCallback callback, void* context) {
    if (!monitor) return false;

    g_activity_callback = callback;
    g_callback_context = context;

    return true;
}

// Cleanup
bool monitor_remove_hooks(ResourceMonitor* monitor) {
    if (!monitor || !monitor->hook_table) return false;

    // First remove the resource hooks
    bool success = resource_hooks_remove(monitor, monitor->hook_table);
    if (!success) {
        printf("Failed to remove resource hooks\n");
    }

    // Then cleanup the hook table
    hook_cleanup(monitor->hook_table);
    monitor->hook_table = NULL;

    return success;
}

// Modified cleanup function
void monitor_cleanup(ResourceMonitor* monitor) {
    if (!monitor) return;

    EnterCriticalSection(&monitor->lock);

    // Remove hooks first if they exist
    if (monitor->hook_table) {
        monitor_remove_hooks(monitor);
    }

    // Clean up activity records
    ActivityRecord* current = monitor->activities;
    while (current) {
        ActivityRecord* next = current->next;
        free(current);
        current = next;
    }

    // Close log file if open
    if (monitor->log_file) {
        CloseHandle(monitor->log_file);
    }

    LeaveCriticalSection(&monitor->lock);
    DeleteCriticalSection(&monitor->lock);

    free(monitor);
}

// Private functions
static void log_activity(ResourceMonitor* monitor, const ActivityRecord* activity) {
    if (!monitor->log_file) return;

    char buffer[1024];
    DWORD written;
    SYSTEMTIME st;
    GetLocalTime(&st);

    int len = _snprintf(buffer, sizeof(buffer), "[%02d:%02d:%02d.%03d] ",
                        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    switch (activity->resource_type) {
        case RESOURCE_FILE_SYSTEM:
            len += _snprintf(buffer + len, sizeof(buffer) - len,
                             "FILE: %s (Access: 0x%x)\r\n",
                             activity->file.path, activity->file.access_type);
            break;
        case RESOURCE_NETWORK:
            len += _snprintf(buffer + len, sizeof(buffer) - len,
                             "NETWORK: %s:%u (Access: 0x%x)\r\n",
                             activity->network.remote_address,
                             activity->network.remote_port,
                             activity->network.access_type);
            break;
        case RESOURCE_REGISTRY:
            fprintf(monitor->log_file, "REGISTRY: %s\\%s (Access: 0x%x)\n",
                    activity->registry.key_path, activity->registry.value_name,
                    activity->registry.access_type);
            break;
        case RESOURCE_PROCESS:
            fprintf(monitor->log_file, "PROCESS: %s (PID: %u)\n",
                    activity->process.image_name, activity->process.process_id);
            break;
        case RESOURCE_DLL:
            fprintf(monitor->log_file, "DLL: %s (Base: %p)\n",
                    activity->dll.dll_path, activity->dll.base_address);
            break;
    }

    fflush(monitor->log_file);
}

static bool is_suspicious_activity(const ActivityRecord* activity) {
    if (!activity) return false;

    switch (activity->resource_type) {
        case RESOURCE_FILE_SYSTEM:
            // Check for access to sensitive directories
            if (strstr(activity->file.path, "\\windows\\system32\\") ||
                strstr(activity->file.path, "\\Program Files\\")) {
                return true;
            }
            break;

        case RESOURCE_NETWORK:
            // Check for suspicious ports
            if (activity->network.remote_port <= 1024) {
                return true;
            }
            break;

        case RESOURCE_REGISTRY:
            // Check for access to sensitive registry keys
            if (strstr(activity->registry.key_path, "HKEY_LOCAL_MACHINE\\SYSTEM\\") ||
                strstr(activity->registry.key_path, "HKEY_LOCAL_MACHINE\\SAM\\")) {
                return true;
            }
            break;

        case RESOURCE_PROCESS:
            // Check for suspicious process creation
            if (strstr(activity->process.image_name, "cmd.exe") ||
                strstr(activity->process.image_name, "powershell.exe")) {
                return true;
            }
            break;
    }

    return false;
}

static void trim_old_records(ResourceMonitor* monitor) {
    if (!monitor || !monitor->activities) return;

    while (monitor->record_count > monitor->config.max_records) {
        ActivityRecord* last = monitor->activities;
        ActivityRecord* prev = NULL;

        // Find the last record
        while (last->next) {
            prev = last;
            last = last->next;
        }

        // Remove the last record
        if (prev) {
            prev->next = NULL;
        } else {
            monitor->activities = NULL;
        }

        free(last);
        monitor->record_count--;
    }
}

// Function to analyze patterns in recorded activities
bool analyze_activity_patterns(ResourceMonitor* monitor, ResourceType type) {
    if (!monitor) return false;

    EnterCriticalSection(&monitor->lock);

    ActivityRecord* current = monitor->activities;
    uint32_t pattern_count = 0;
    bool suspicious_pattern = false;

    // Pattern detection variables
    struct {
        uint32_t repeated_access;
        uint32_t rapid_sequence;
        uint32_t high_volume;
    } patterns = {0};

    while (current && !suspicious_pattern) {
        if (current->resource_type == type) {
            pattern_count++;

            // Check for rapid repeated access
            if (current->next && current->resource_type == current->next->resource_type) {
                patterns.repeated_access++;
            }

            // Check resource-specific patterns
            switch (type) {
                case RESOURCE_FILE_SYSTEM:
                    if (current->file.bytes_transferred > 1024 * 1024) { // 1MB
                        patterns.high_volume++;
                    }
                    break;

                case RESOURCE_NETWORK:
                    if (current->network.bytes_sent + current->network.bytes_received > 1024 * 1024) {
                        patterns.high_volume++;
                    }
                    break;

                case RESOURCE_PROCESS:
                    if (patterns.rapid_sequence > 5) { // More than 5 processes in sequence
                        suspicious_pattern = true;
                    }
                    break;
            }
        }

        current = current->next;
    }

    // Analyze collected patterns
    suspicious_pattern |= (patterns.repeated_access > 10) ||    // More than 10 repeated accesses
                          (patterns.high_volume > 5);            // More than 5 high-volume operations

    LeaveCriticalSection(&monitor->lock);

    return suspicious_pattern;
}

// Function to generate activity report
bool generate_activity_report(ResourceMonitor* monitor, const char* report_path) {
    if (!monitor || !report_path) return false;

    FILE* report_file = fopen(report_path, "w");
    if (!report_file) return false;

    EnterCriticalSection(&monitor->lock);

    // Write header
    fprintf(report_file, "Resource Monitor Activity Report\n");
    fprintf(report_file, "================================\n\n");

    // Write statistics
    fprintf(report_file, "Activity Statistics:\n");
    fprintf(report_file, "- File Operations: %llu\n", monitor->stats.total_file_ops);
    fprintf(report_file, "- Network Operations: %llu\n", monitor->stats.total_network_ops);
    fprintf(report_file, "- Memory Operations: %llu\n", monitor->stats.total_memory_ops);
    fprintf(report_file, "- Registry Operations: %llu\n", monitor->stats.total_registry_ops);
    fprintf(report_file, "- Process Operations: %llu\n", monitor->stats.total_process_ops);
    fprintf(report_file, "- Blocked Operations: %llu\n\n", monitor->stats.total_blocked_ops);

    // Write recent activities
    fprintf(report_file, "Recent Activities:\n");
    ActivityRecord* current = monitor->activities;
    int count = 0;

    while (current && count < 100) { // List up to 100 most recent activities
        SYSTEMTIME st;
        FileTimeToSystemTime(&current->file.timestamp, &st);

        fprintf(report_file, "[%02d:%02d:%02d.%03d] ",
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

        switch (current->resource_type) {
            case RESOURCE_FILE_SYSTEM:
                fprintf(report_file, "FILE: %s\n", current->file.path);
                break;
            case RESOURCE_NETWORK:
                fprintf(report_file, "NETWORK: %s:%u\n",
                        current->network.remote_address,
                        current->network.remote_port);
                break;
            case RESOURCE_REGISTRY:
                fprintf(report_file, "REGISTRY: %s\n",
                        current->registry.key_path);
                break;
            case RESOURCE_PROCESS:
                fprintf(report_file, "PROCESS: %s (PID: %u)\n",
                        current->process.image_name,
                        current->process.process_id);
                break;
            case RESOURCE_DLL:
                fprintf(report_file, "DLL: %s\n", current->dll.dll_path);
                break;
        }

        current = current->next;
        count++;
    }

    LeaveCriticalSection(&monitor->lock);

    fclose(report_file);
    return true;
}

// Function to clear old activities based on age
void clear_old_activities(ResourceMonitor* monitor, uint32_t age_seconds) {
    if (!monitor) return;

    EnterCriticalSection(&monitor->lock);

    FILETIME current_time;
    GetSystemTimeAsFileTime(&current_time);
    ULARGE_INTEGER current_ul = {.LowPart = current_time.dwLowDateTime,
            .HighPart = current_time.dwHighDateTime};

    ActivityRecord* current = monitor->activities;
    ActivityRecord* prev = NULL;

    while (current) {
        ULARGE_INTEGER record_ul = {.LowPart = current->file.timestamp.dwLowDateTime,
                .HighPart = current->file.timestamp.dwHighDateTime};

        // Calculate age in seconds
        uint64_t age = (current_ul.QuadPart - record_ul.QuadPart) / 10000000ULL;

        if (age > age_seconds) {
            // Remove this record
            ActivityRecord* to_remove = current;

            if (prev) {
                prev->next = current->next;
                current = current->next;
            } else {
                monitor->activities = current->next;
                current = monitor->activities;
            }

            free(to_remove);
            monitor->record_count--;
        } else {
            prev = current;
            current = current->next;
        }
    }

    LeaveCriticalSection(&monitor->lock);
}

// Function to check if a specific process is behaving suspiciously
bool is_process_suspicious(ResourceMonitor* monitor, uint32_t process_id) {
    if (!monitor) return false;

    EnterCriticalSection(&monitor->lock);

    ActivityRecord* current = monitor->activities;
    bool suspicious = false;

    struct {
        uint32_t file_ops;
        uint32_t network_ops;
        uint32_t registry_ops;
        uint32_t process_ops;
    } activity_count = {0};

    // Count activities for this process
    while (current) {
        if (current->resource_type == RESOURCE_PROCESS &&
            current->process.process_id == process_id) {

            switch (current->resource_type) {
                case RESOURCE_FILE_SYSTEM:
                    activity_count.file_ops++;
                    break;
                case RESOURCE_NETWORK:
                    activity_count.network_ops++;
                    break;
                case RESOURCE_REGISTRY:
                    activity_count.registry_ops++;
                    break;
                case RESOURCE_PROCESS:
                    activity_count.process_ops++;
                    break;
            }
        }
        current = current->next;
    }

    // Check for suspicious patterns
    suspicious = (activity_count.file_ops > 1000) ||      // Too many file operations
                 (activity_count.network_ops > 100) ||      // Too many network operations
                 (activity_count.registry_ops > 500) ||     // Too many registry operations
                 (activity_count.process_ops > 50);         // Too many process operations

    LeaveCriticalSection(&monitor->lock);

    return suspicious;
}