#ifndef SECURITY_TYPES_H
#define SECURITY_TYPES_H

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>  // Must come before windows.h
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

// Layer identification
typedef enum {
    LAYER_JAIL,
    LAYER_SHADOW_VM
} LayerType;

// Forward declarations
struct JailContext;
struct ShadowVMContext;

// Security layer structure
typedef struct SecurityLayer {
    LayerType type;
    void* context;  // Points to either JailContext or ShadowVMContext
    struct SecurityLayer* next;
} SecurityLayer;

// Jail context structure
typedef struct JailContext {
    char* root_path;
    char* name;
    HANDLE job_object;

    struct {
        bool allow_network;
        bool allow_files;
        bool allow_registry;
        size_t max_processes;
        size_t memory_limit;
    } policy;

    struct {
        bool active;
        uint32_t process_count;
        FILETIME start_time;
    } state;
} JailContext;

// ShadowVM context structure
typedef struct ShadowVMContext {
    void* sandbox_memory;
    size_t sandbox_size;

    struct {
        bool intercept_syscalls;
        bool monitor_resources;
        bool pattern_matching;
    } features;

    struct {
        size_t memory_used;
        uint64_t syscall_count;
        uint64_t violations;
    } metrics;
} ShadowVMContext;

// Main security system structure
typedef struct SecuritySystem {
    SecurityLayer* layers;
    struct {
        char log_path[MAX_PATH];
        bool debug_mode;
        uint32_t security_level;
    } config;

    CRITICAL_SECTION lock;
    HFILE* log_file;
} SecuritySystem;

typedef struct {
    HFILE* file;
    bool debug_mode;
    char log_path[MAX_PATH];
    CRITICAL_SECTION lock;
} SecurityLogger;

#endif // SECURITY_TYPES_H