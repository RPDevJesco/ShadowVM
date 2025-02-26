#ifndef RESOURCE_MONITOR_H
#define RESOURCE_MONITOR_H

#include "resource_types.h"
#include "security_types.h"
#include "hook_system.h"
#include "resource_hooks.h"

// Main resource monitor structure
typedef struct ResourceMonitor {
    MonitorConfig config;
    CRITICAL_SECTION lock;
    ActivityRecord* activities;
    struct HookTable* hook_table;
    uint32_t record_count;
    HANDLE log_file;
    struct {
        uint64_t total_file_ops;
        uint64_t total_network_ops;
        uint64_t total_memory_ops;
        uint64_t total_registry_ops;
        uint64_t total_process_ops;
        uint64_t total_blocked_ops;
    } stats;

} ResourceMonitor;


// Monitor initialization and cleanup
ResourceMonitor* monitor_init(const MonitorConfig* config);
void monitor_cleanup(ResourceMonitor* monitor);

// Activity recording
bool monitor_record_activity(ResourceMonitor* monitor, ActivityRecord* activity);
void monitor_clear_activities(ResourceMonitor* monitor);

// Configuration
bool monitor_set_config(ResourceMonitor* monitor, const MonitorConfig* config);
bool monitor_enable_resource(ResourceMonitor* monitor, ResourceType resource);
bool monitor_disable_resource(ResourceMonitor* monitor, ResourceType resource);

// Query and analysis
ActivityRecord* monitor_get_activities(ResourceMonitor* monitor, ResourceType type);
uint64_t monitor_get_activity_count(ResourceMonitor* monitor, ResourceType type);
bool monitor_get_statistics(ResourceMonitor* monitor, void* stats, size_t size);

// Hook management
bool monitor_install_hooks(ResourceMonitor* monitor);
bool monitor_remove_hooks(ResourceMonitor* monitor);
bool monitor_are_hooks_installed(ResourceMonitor* monitor);
bool monitor_set_hooks_enabled(ResourceMonitor* monitor, bool enable);

// Activity monitoring
bool monitor_set_callback(ResourceMonitor* monitor, ActivityCallback callback, void* context);

// Analysis functions
bool analyze_activity_patterns(ResourceMonitor* monitor, ResourceType type);
bool generate_activity_report(ResourceMonitor* monitor, const char* report_path);
void clear_old_activities(ResourceMonitor* monitor, uint32_t age_seconds);
bool is_process_suspicious(ResourceMonitor* monitor, uint32_t process_id);

#endif // RESOURCE_MONITOR_H