#ifndef SHADOW_VM_H
#define SHADOW_VM_H

#include "security_types.h"

// ShadowVM initialization and cleanup
ShadowVMContext* shadowvm_init(size_t sandbox_size);
void shadowvm_cleanup(ShadowVMContext* vm);

// Memory management
bool shadowvm_allocate_sandbox(ShadowVMContext* vm, size_t size);
bool shadowvm_protect_memory(ShadowVMContext* vm, uint32_t protection);

// Code execution
bool shadowvm_execute_code(ShadowVMContext* vm, const uint8_t* code, size_t code_size);
bool shadowvm_attach_to_process(ShadowVMContext* vm, HANDLE process);

// Syscall interception
bool shadowvm_install_hooks(ShadowVMContext* vm);
bool shadowvm_remove_hooks(ShadowVMContext* vm);

// Monitoring
void shadowvm_update_metrics(ShadowVMContext* vm);
bool shadowvm_check_patterns(ShadowVMContext* vm, const uint8_t* data, size_t size);

#endif // SHADOW_VM_H