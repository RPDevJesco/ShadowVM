#ifndef RESOURCE_TYPES_H
#define RESOURCE_TYPES_H

#include <Windows.h>
#include <stdint.h>
#include <stdbool.h>

// Forward declarations
struct ResourceMonitor;
struct HookTable;

// Resource types to monitor
typedef enum {
    RESOURCE_FILE_SYSTEM   = 0x0001,
    RESOURCE_NETWORK      = 0x0002,
    RESOURCE_MEMORY       = 0x0004,
    RESOURCE_REGISTRY     = 0x0008,
    RESOURCE_PROCESS      = 0x0010,
    RESOURCE_THREAD       = 0x0020,
    RESOURCE_HANDLE       = 0x0040,
    RESOURCE_DLL          = 0x0080,
    RESOURCE_ALL          = 0xFFFF
} ResourceType;

// Access patterns to track
typedef enum {
    ACCESS_READ            = 0x0001,
    ACCESS_WRITE           = 0x0002,
    ACCESS_EXECUTE         = 0x0004,
    ACCESS_DELETE          = 0x0008,
    ACCESS_CREATE          = 0x0010,
    ACCESS_NETWORK_CONNECT = 0x0020,
    ACCESS_NETWORK_LISTEN  = 0x0040,
    ACCESS_REGISTRY_QUERY  = 0x0080,
    ACCESS_REGISTRY_SET    = 0x0100
} AccessType;

// File system activity
typedef struct {
    char path[MAX_PATH];
    AccessType access_type;
    uint64_t bytes_transferred;
    FILETIME timestamp;
    bool success;
} FileActivity;

// Network activity
typedef struct {
    char remote_address[46];  // IPv6 size
    uint16_t remote_port;
    uint16_t local_port;
    AccessType access_type;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    FILETIME timestamp;
} NetworkActivity;

// Memory activity
typedef struct {
    void* address;
    size_t size;
    uint32_t protection;
    AccessType access_type;
    FILETIME timestamp;
} MemoryActivity;

// Registry activity
typedef struct {
    char key_path[MAX_PATH];
    char value_name[256];
    AccessType access_type;
    FILETIME timestamp;
    bool success;
} RegistryActivity;

// Process/Thread activity
typedef struct {
    uint32_t process_id;
    uint32_t thread_id;
    char image_name[MAX_PATH];
    AccessType access_type;
    FILETIME timestamp;
} ProcessActivity;

// DLL loading activity
typedef struct {
    char dll_path[MAX_PATH];
    void* base_address;
    FILETIME timestamp;
    bool success;
} DLLActivity;

// Combined activity record
typedef struct ActivityRecord {
    ResourceType resource_type;
    union {
        FileActivity file;
        NetworkActivity network;
        MemoryActivity memory;
        RegistryActivity registry;
        ProcessActivity process;
        DLLActivity dll;
    };
    struct ActivityRecord* next;
} ActivityRecord;

// Resource monitor configuration
typedef struct {
    uint32_t enabled_resources;  // Bitmap of ResourceType
    bool log_to_file;
    char log_path[MAX_PATH];
    uint32_t max_records;        // Maximum records to keep in memory
    bool block_suspicious;       // Whether to block suspicious activities
} MonitorConfig;

// Activity callback type
typedef bool (*ActivityCallback)(struct ResourceMonitor* monitor,
                                 const ActivityRecord* activity,
                                 void* context);

#endif // RESOURCE_TYPES_H