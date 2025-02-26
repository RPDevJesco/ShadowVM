#include "hook_system.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

HookTable* hook_init(uint32_t max_hooks) {
    HookTable* table = (HookTable*)calloc(1, sizeof(HookTable));
    if (!table) return NULL;

    table->entries = (HookEntry*)calloc(max_hooks, sizeof(HookEntry));
    if (!table->entries) {
        free(table);
        return NULL;
    }

    table->capacity = max_hooks;
    table->count = 0;
    InitializeCriticalSection(&table->lock);

    return table;
}

bool hook_add(HookTable* table, const char* function_name, const char* module_name,
              void* hook_function, void* context) {
    if (!table || !function_name || !module_name || !hook_function) {
        printf("Hook add failed: Invalid parameters\n");
        return false;
    }

    EnterCriticalSection(&table->lock);

    // Check if we have space
    if (table->count >= table->capacity) {
        printf("Hook add failed: Table full (capacity: %u)\n", table->capacity);
        LeaveCriticalSection(&table->lock);
        return false;
    }

    // Check if hook already exists
    for (uint32_t i = 0; i < table->count; i++) {
        if (strcmp(table->entries[i].target_function, function_name) == 0 &&
            strcmp(table->entries[i].target_module, module_name) == 0) {
            printf("Hook add failed: Hook already exists for %s in %s\n",
                   function_name, module_name);
            LeaveCriticalSection(&table->lock);
            return false;
        }
    }

    // Get module handle
    HMODULE module = hook_get_module_handle(module_name);
    if (!module) {
        DWORD error = GetLastError();
        printf("Hook add failed: Could not get module handle for %s (Error: %d)\n",
               module_name, error);
        LeaveCriticalSection(&table->lock);
        return false;
    }

    // Create new hook entry
    HookEntry* entry = &table->entries[table->count];
    entry->target_function = _strdup(function_name);
    entry->target_module = _strdup(module_name);
    if (!entry->target_function || !entry->target_module) {
        printf("Hook add failed: Memory allocation failed\n");
        free(entry->target_function);
        free(entry->target_module);
        LeaveCriticalSection(&table->lock);
        return false;
    }

    entry->hook_address = hook_function;
    entry->context = context;
    entry->enabled = false;

    // Install hook
    if (!hook_modify_iat(module, module_name, function_name,
                         hook_function, &entry->original_address)) {
        DWORD error = GetLastError();
        printf("Hook add failed: Could not modify IAT for %s in %s (Error: %d)\n",
               function_name, module_name, error);
        free(entry->target_function);
        free(entry->target_module);
        LeaveCriticalSection(&table->lock);
        return false;
    }

    entry->enabled = true;
    table->count++;

    LeaveCriticalSection(&table->lock);
    printf("Successfully added hook for %s in %s\n", function_name, module_name);
    return true;
}

bool hook_remove(HookTable* table, const char* function_name, const char* module_name) {
    if (!table || !function_name || !module_name) return false;

    EnterCriticalSection(&table->lock);

    // Find the hook
    for (uint32_t i = 0; i < table->count; i++) {
        if (strcmp(table->entries[i].target_function, function_name) == 0 &&
            strcmp(table->entries[i].target_module, module_name) == 0) {

            // Restore original function
            HMODULE module = hook_get_module_handle(module_name);
            if (module) {
                hook_restore_iat(module, module_name, function_name,
                                 table->entries[i].original_address);
            }

            // Free entry
            free(table->entries[i].target_function);
            free(table->entries[i].target_module);

            // Move last entry to this slot if not last
            if (i < table->count - 1) {
                memcpy(&table->entries[i], &table->entries[table->count - 1],
                       sizeof(HookEntry));
            }

            table->count--;
            LeaveCriticalSection(&table->lock);
            return true;
        }
    }

    LeaveCriticalSection(&table->lock);
    return false;
}

void* hook_get_original(HookTable* table, const char* function_name,
                        const char* module_name) {
    if (!table || !function_name || !module_name) return NULL;

    EnterCriticalSection(&table->lock);

    // Find the hook
    for (uint32_t i = 0; i < table->count; i++) {
        if (strcmp(table->entries[i].target_function, function_name) == 0 &&
            strcmp(table->entries[i].target_module, module_name) == 0) {
            void* original = table->entries[i].original_address;
            LeaveCriticalSection(&table->lock);
            return original;
        }
    }

    LeaveCriticalSection(&table->lock);
    return NULL;
}

bool hook_restore_iat(HMODULE module, const char* target_module,
                      const char* function_name, void* original_function) {
    return hook_modify_iat(module, target_module, function_name,
                           original_function, NULL);
}

void* hook_find_iat_entry(IMAGE_IMPORT_DESCRIPTOR* import_desc,
                          HMODULE module, const char* function_name) {
    if (!import_desc || !module || !function_name) return NULL;

    // Get Import Address Table
    IMAGE_THUNK_DATA* iat = (IMAGE_THUNK_DATA*)
            ((BYTE*)module + import_desc->FirstThunk);

    // Get Import Name Table
    IMAGE_THUNK_DATA* int_ = (IMAGE_THUNK_DATA*)
            ((BYTE*)module + import_desc->OriginalFirstThunk);

    // Find matching function
    while (int_->u1.AddressOfData) {
        if (!(int_->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
            IMAGE_IMPORT_BY_NAME* import_name = (IMAGE_IMPORT_BY_NAME*)
                    ((BYTE*)module + int_->u1.AddressOfData);

            if (strcmp((char*)import_name->Name, function_name) == 0) {
                return &iat->u1.Function;
            }
        }
        int_++;
        iat++;
    }

    return NULL;
}

HMODULE hook_get_module_handle(const char* module_name) {
    HMODULE module = GetModuleHandleA(module_name);
    if (!module) {
        module = LoadLibraryA(module_name);
    }
    return module;
}

void* hook_get_proc_address(HMODULE module, const char* function_name) {
    return GetProcAddress(module, function_name);
}

IMAGE_IMPORT_DESCRIPTOR* hook_find_import_descriptor(HMODULE module,
                                                     const char* target_module) {
    // Get DOS header
    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)module;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Import descriptor search failed: Invalid DOS header\n");
        return NULL;
    }

    // Get NT headers
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)
            ((BYTE*)module + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        printf("Import descriptor search failed: Invalid NT header\n");
        return NULL;
    }

    // Get import directory
    IMAGE_DATA_DIRECTORY* import_dir = &nt_headers->OptionalHeader.
            DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!import_dir->VirtualAddress) {
        printf("Import descriptor search failed: No import directory\n");
        return NULL;
    }

    // Get first import descriptor
    IMAGE_IMPORT_DESCRIPTOR* import_desc = (IMAGE_IMPORT_DESCRIPTOR*)
            ((BYTE*)module + import_dir->VirtualAddress);

    // Find matching module - case insensitive and handle .dll extension
    char search_module[MAX_PATH];
    strncpy(search_module, target_module, MAX_PATH - 1);
    search_module[MAX_PATH - 1] = '\0';

    // Add .dll if not present
    if (!strstr(search_module, ".dll")) {
        strncat(search_module, ".dll", MAX_PATH - strlen(search_module) - 1);
    }

    while (import_desc->Name) {
        char* module_name = (char*)((BYTE*)module + import_desc->Name);
        if (_stricmp(module_name, search_module) == 0 ||
            _stricmp(module_name, target_module) == 0) {
            return import_desc;
        }
        import_desc++;
    }

    printf("Import descriptor search failed: Module %s not found in imports\n",
           target_module);
    return NULL;
}

bool hook_modify_iat(HMODULE module, const char* target_module,
                     const char* function_name, void* new_function,
                     void** original_function) {
    // Load target module if not already loaded
    HMODULE target = GetModuleHandleA(target_module);
    if (!target) {
        target = LoadLibraryA(target_module);
        if (!target) {
            printf("IAT modification failed: Could not load module %s\n",
                   target_module);
            return false;
        }
    }

    // Get original function address
    void* orig_func = GetProcAddress(target, function_name);
    if (!orig_func) {
        printf("IAT modification failed: Could not find function %s in %s\n",
               function_name, target_module);
        return false;
    }

    // Find import descriptor
    IMAGE_IMPORT_DESCRIPTOR* import_desc = hook_find_import_descriptor(module, target_module);
    if (!import_desc) {
        // If module not found in IAT, we need to add it
        printf("Module not found in IAT, attempting inline hook...\n");
        return hook_create_inline(orig_func, new_function, original_function);
    }

    // Find IAT entry
    void* iat_entry = hook_find_iat_entry(import_desc, module, function_name);
    if (!iat_entry) {
        printf("IAT modification failed: Could not find IAT entry for %s\n",
               function_name);
        return false;
    }

    // Save original function
    if (original_function) {
        *original_function = *(void**)iat_entry;
    }

    // Modify protection
    DWORD old_protect;
    if (!VirtualProtect(iat_entry, sizeof(void*), PAGE_READWRITE, &old_protect)) {
        printf("IAT modification failed: Could not modify memory protection (%d)\n",
               GetLastError());
        return false;
    }

    // Replace function pointer
    *(void**)iat_entry = new_function;

    // Restore protection
    VirtualProtect(iat_entry, sizeof(void*), old_protect, &old_protect);

    return true;
}

void hook_cleanup(HookTable* table) {
    if (!table) return;

    EnterCriticalSection(&table->lock);

    // Remove all hooks
    for (uint32_t i = 0; i < table->count; i++) {
        hook_restore_iat(hook_get_module_handle(table->entries[i].target_module),
                         table->entries[i].target_module,
                         table->entries[i].target_function,
                         table->entries[i].original_address);

        free(table->entries[i].target_function);
        free(table->entries[i].target_module);
    }

    LeaveCriticalSection(&table->lock);
    DeleteCriticalSection(&table->lock);

    free(table->entries);
    free(table);
}