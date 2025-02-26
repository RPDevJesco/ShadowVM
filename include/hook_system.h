#ifndef HOOK_SYSTEM_H
#define HOOK_SYSTEM_H

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include "security_types.h"

// Hook function prototype
typedef void* (*HookFunction)(void* original_function, void* context);

// Hook entry structure
typedef struct {
    char* target_function;    // Name of function to hook
    char* target_module;      // Module containing the function
    void* original_address;   // Original function address
    void* hook_address;       // Hook function address
    void* context;           // User context for hook
    bool enabled;            // Whether hook is active
} HookEntry;

// Hook table
typedef struct {
    HookEntry* entries;      // Array of hook entries
    uint32_t count;          // Number of active hooks
    uint32_t capacity;       // Maximum hooks
    CRITICAL_SECTION lock;   // Thread safety
} HookTable;

// Initialize the hook system
HookTable* hook_init(uint32_t max_hooks);

// Add a new hook
bool hook_add(HookTable* table,
              const char* function_name,
              const char* module_name,
              void* hook_function,
              void* context);

// Remove a hook
bool hook_remove(HookTable* table,
                 const char* function_name,
                 const char* module_name);

// Enable/disable hooks
bool hook_enable(HookTable* table,
                 const char* function_name,
                 const char* module_name);

bool hook_disable(HookTable* table,
                  const char* function_name,
                  const char* module_name);

// Get original function
void* hook_get_original(HookTable* table,
                        const char* function_name,
                        const char* module_name);

// Cleanup
void hook_cleanup(HookTable* table);

// IAT manipulation functions
bool hook_modify_iat(HMODULE module,
                     const char* target_module,
                     const char* function_name,
                     void* new_function,
                     void** original_function);

bool hook_restore_iat(HMODULE module,
                      const char* target_module,
                      const char* function_name,
                      void* original_function);

// PE header parsing utilities
IMAGE_IMPORT_DESCRIPTOR* hook_find_import_descriptor(HMODULE module,
                                                     const char* target_module);

void* hook_find_iat_entry(IMAGE_IMPORT_DESCRIPTOR* import_desc,
                          HMODULE module,
                          const char* function_name);

// Utility functions
HMODULE hook_get_module_handle(const char* module_name);
void* hook_get_proc_address(HMODULE module, const char* function_name);

// Function to remove inline hooks
bool hook_remove_inline(void* target_function,
                        void* original_function);

#endif // HOOK_SYSTEM_H