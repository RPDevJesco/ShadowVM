#include "security_system.h"
#include "jail_layer.h"
#include "shadow_vm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Private function declarations
static void log_violation(SecuritySystem* system, const char* message);
static bool setup_logging(SecuritySystem* system, const char* log_path);

SecuritySystem* security_init(const char* log_path) {
    SecuritySystem* system = (SecuritySystem*)calloc(1, sizeof(SecuritySystem));
    if (!system) return NULL;

    // Initialize critical section
    InitializeCriticalSection(&system->lock);

    // Setup logging
    if (!setup_logging(system, log_path)) {
        DeleteCriticalSection(&system->lock);
        free(system);
        return NULL;
    }

    // Set default configuration
    system->config.debug_mode = false;
    system->config.security_level = 2;

    return system;
}

bool add_jail_layer(SecuritySystem* system, const char* name, const char* root_path) {
    if (!system || !name || !root_path) return false;

    // Create jail context
    JailContext* jail = jail_init(name, root_path);
    if (!jail) return false;

    // Create security layer
    SecurityLayer* layer = (SecurityLayer*)calloc(1, sizeof(SecurityLayer));
    if (!layer) {
        jail_cleanup(jail);
        return false;
    }

    layer->type = LAYER_JAIL;
    layer->context = jail;

    // Add to layer list
    EnterCriticalSection(&system->lock);
    layer->next = system->layers;
    system->layers = layer;
    LeaveCriticalSection(&system->lock);

    return true;
}

bool add_shadowvm_layer(SecuritySystem* system, size_t sandbox_size) {
    if (!system) return false;

    // Create ShadowVM context
    ShadowVMContext* vm = shadowvm_init(sandbox_size);
    if (!vm) return false;

    // Create security layer
    SecurityLayer* layer = (SecurityLayer*)calloc(1, sizeof(SecurityLayer));
    if (!layer) {
        shadowvm_cleanup(vm);
        return false;
    }

    layer->type = LAYER_SHADOW_VM;
    layer->context = vm;

    // Add to layer list
    EnterCriticalSection(&system->lock);
    layer->next = system->layers;
    system->layers = layer;
    LeaveCriticalSection(&system->lock);

    return true;
}

bool security_execute(SecuritySystem* system, const char* command) {
    if (!system || !command) return false;

    // Find required layers
    JailContext* jail = NULL;
    ShadowVMContext* vm = NULL;

    SecurityLayer* layer = system->layers;
    while (layer) {
        if (layer->type == LAYER_JAIL) {
            jail = (JailContext*)layer->context;
        } else if (layer->type == LAYER_SHADOW_VM) {
            vm = (ShadowVMContext*)layer->context;
        }
        layer = layer->next;
    }

    if (!jail || !vm) {
        log_violation(system, "Missing required security layers");
        return false;
    }

    // Create process in jail
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    if (!CreateProcess(NULL, (LPSTR)command, NULL, NULL, FALSE,
                       CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
                       NULL, jail->root_path, &si, &pi)) {
        log_violation(system, "Failed to create process");
        return false;
    }

    // Initialize both layers
    if (!jail_start_process(jail, pi.hProcess)) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        log_violation(system, "Failed to initialize jail");
        return false;
    }

    if (!shadowvm_attach_to_process(vm, pi.hProcess)) {
        jail_stop_process(jail, pi.hProcess);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        log_violation(system, "Failed to initialize ShadowVM");
        return false;
    }

    // Resume process
    ResumeThread(pi.hThread);

    // Monitor execution
    while (WaitForSingleObject(pi.hProcess, 100) == WAIT_TIMEOUT) {
        // Update metrics
        jail_update_metrics(jail);
        shadowvm_update_metrics(vm);

        // Check for violations
        if (!jail_check_limits(jail) ||
            check_security_violations(system, jail, vm)) {
            log_violation(system, "Security violation detected");
            TerminateProcess(pi.hProcess, 1);
            break;
        }
    }

    // Cleanup
    shadowvm_remove_hooks(vm);
    jail_stop_process(jail, pi.hProcess);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return true;
}

bool check_security_violations(SecuritySystem* system,
                               JailContext* jail, ShadowVMContext* vm) {

    // Check resource limits
    if (vm->metrics.memory_used > jail->policy.memory_limit) {
        log_violation(system, "Memory limit exceeded");
        return true;
    }

    if (jail->state.process_count > jail->policy.max_processes) {
        log_violation(system, "Process limit exceeded");
        return true;
    }

    // Check for suspicious patterns
    if (vm->metrics.violations > 0) {
        log_violation(system, "Suspicious behavior detected");
        return true;
    }

    return false;
}

void update_security_metrics(SecuritySystem* system) {
    if (!system) return;

    EnterCriticalSection(&system->lock);

    SecurityLayer* layer = system->layers;
    while (layer) {
        if (layer->type == LAYER_JAIL) {
            jail_update_metrics((JailContext*)layer->context);
        } else if (layer->type == LAYER_SHADOW_VM) {
            shadowvm_update_metrics((ShadowVMContext*)layer->context);
        }
        layer = layer->next;
    }

    LeaveCriticalSection(&system->lock);
}

void security_cleanup(SecuritySystem* system) {
    if (!system) return;

    EnterCriticalSection(&system->lock);

    // Clean up layers
    SecurityLayer* layer = system->layers;
    while (layer) {
        SecurityLayer* next = layer->next;

        if (layer->type == LAYER_JAIL) {
            jail_cleanup((JailContext*)layer->context);
        } else if (layer->type == LAYER_SHADOW_VM) {
            shadowvm_cleanup((ShadowVMContext*)layer->context);
        }

        free(layer);
        layer = next;
    }

    if (system->log_file) {
        fclose(system->log_file);
    }

    LeaveCriticalSection(&system->lock);
    DeleteCriticalSection(&system->lock);

    free(system);
}

// Private functions
static void log_violation(SecuritySystem* system, const char* message) {
    if (!system->log_file) return;

    SYSTEMTIME st;
    GetLocalTime(&st);

    fprintf(system->log_file, "[%02d:%02d:%02d.%03d] VIOLATION: %s\n",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            message);
    fflush(system->log_file);
}

static bool setup_logging(SecuritySystem* system, const char* log_path) {
    if (!system) return false;

    // If no log path specified, disable logging
    if (!log_path) {
        system->log_file = NULL;
        system->config.log_path[0] = '\0';
        return true;
    }

    // Copy log path to config
    strncpy(system->config.log_path, log_path, MAX_PATH - 1);
    system->config.log_path[MAX_PATH - 1] = '\0';

    // Open log file
    system->log_file = fopen(log_path, "w");
    if (!system->log_file) {
        return false;
    }

    // Enable line buffering for more reliable logging
    setvbuf(system->log_file, NULL, _IOLBF, 1024);

    // Write initial log entry
    SYSTEMTIME st;
    GetLocalTime(&st);

    fprintf(system->log_file,
            "[%02d:%02d:%02d.%03d] Security system initialized\n",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    fprintf(system->log_file, "Configuration:\n");
    fprintf(system->log_file, "- Security Level: %u\n", system->config.security_level);
    fprintf(system->log_file, "- Debug Mode: %s\n",
            system->config.debug_mode ? "Enabled" : "Disabled");
    fprintf(system->log_file, "- Log Path: %s\n", system->config.log_path);
    fprintf(system->log_file, "=================================\n");
    fflush(system->log_file);

    return true;
}

// Helper function for log rotation
static bool rotate_log_if_needed(SecuritySystem* system) {
    if (!system || !system->log_file) return false;

    // Get current file size
    fseek(system->log_file, 0, SEEK_END);
    long size = ftell(system->log_file);

    // If file is larger than 10MB, rotate it
    if (size > 10 * 1024 * 1024) {
        char backup_path[MAX_PATH];
        snprintf(backup_path, sizeof(backup_path), "%s.old", system->config.log_path);

        // Close current log file
        fclose(system->log_file);

        // Rename current to backup
        if (rename(system->config.log_path, backup_path) != 0) {
            // Try to reopen original file if rename fails
            system->log_file = fopen(system->config.log_path, "a");
            return false;
        }

        // Open new log file
        system->log_file = fopen(system->config.log_path, "w");
        if (!system->log_file) {
            return false;
        }

        // Reset buffering on new file
        setvbuf(system->log_file, NULL, _IOLBF, 1024);

        // Write rotation message
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(system->log_file,
                "[%02d:%02d:%02d.%03d] Log rotated, previous log saved to %s\n",
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                backup_path);
        fflush(system->log_file);
    }

    return true;
}

// Helper function for logging with timestamp
static void log_with_timestamp(SecuritySystem* system, const char* level, const char* message) {
    if (!system || !system->log_file) return;

    SYSTEMTIME st;
    GetLocalTime(&st);

    fprintf(system->log_file, "[%02d:%02d:%02d.%03d] %s: %s\n",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            level, message);
    fflush(system->log_file);

    // Check if log rotation is needed
    rotate_log_if_needed(system);
}

// Public interface for different log levels
void log_info(SecuritySystem* system, const char* message) {
    log_with_timestamp(system, "INFO", message);
}

void log_warning(SecuritySystem* system, const char* message) {
    log_with_timestamp(system, "WARNING", message);
}

void log_error(SecuritySystem* system, const char* message) {
    log_with_timestamp(system, "ERROR", message);
}

void log_debug(SecuritySystem* system, const char* message) {
    if (system && system->config.debug_mode) {
        log_with_timestamp(system, "DEBUG", message);
    }
}