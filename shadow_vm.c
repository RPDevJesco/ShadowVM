#include "shadow_vm.h"
#include <stdio.h>
#include <stdlib.h>

// Private function declarations
static LONG CALLBACK syscall_handler(EXCEPTION_POINTERS* exp);
static bool pattern_match(const uint8_t* data, size_t size, const uint8_t* pattern, size_t pattern_size);

// Known suspicious patterns
static const struct {
    uint8_t* pattern;
    size_t size;
    const char* description;
} SUSPICIOUS_PATTERNS[] = {
        // Example patterns - in practice, these would be more sophisticated
        { (uint8_t*)"\x90\x90\x90\x90", 4, "NOP sled detected" },
        { (uint8_t*)"\xCC\xCC\xCC\xCC", 4, "Breakpoint sequence detected" },
        // Add more patterns here
};

ShadowVMContext* shadowvm_init(size_t sandbox_size) {
    ShadowVMContext* vm = (ShadowVMContext*)calloc(1, sizeof(ShadowVMContext));
    if (!vm) return NULL;

    // Initialize features
    vm->features.intercept_syscalls = true;
    vm->features.monitor_resources = true;
    vm->features.pattern_matching = true;

    // Allocate sandbox memory
    if (!shadowvm_allocate_sandbox(vm, sandbox_size)) {
        free(vm);
        return NULL;
    }

    return vm;
}

bool shadowvm_allocate_sandbox(ShadowVMContext* vm, size_t size) {
    if (!vm) return false;

    // Allocate sandbox memory with initial no-access protection
    vm->sandbox_memory = VirtualAlloc(
            NULL,
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_NOACCESS
    );

    if (!vm->sandbox_memory) {
        return false;
    }

    vm->sandbox_size = size;
    return true;
}

bool shadowvm_protect_memory(ShadowVMContext* vm, uint32_t protection) {
    if (!vm || !vm->sandbox_memory) return false;

    DWORD old_protect;
    return VirtualProtect(
            vm->sandbox_memory,
            vm->sandbox_size,
            protection,
            &old_protect
    );
}

bool shadowvm_execute_code(ShadowVMContext* vm, const uint8_t* code, size_t code_size) {
    if (!vm || !code || code_size > vm->sandbox_size) return false;

    // Check for suspicious patterns before execution
    if (vm->features.pattern_matching) {
        if (shadowvm_check_patterns(vm, code, code_size)) {
            vm->metrics.violations++;
            return false;
        }
    }

    // Copy code to sandbox
    memcpy(vm->sandbox_memory, code, code_size);

    // Set execute protection
    if (!shadowvm_protect_memory(vm, PAGE_EXECUTE_READ)) {
        return false;
    }

    // Execute code
    typedef void (*CodeFunc)();
    CodeFunc func = (CodeFunc)vm->sandbox_memory;

    __try {
        func();
    }
    __except(syscall_handler(GetExceptionInformation())) {
        return false;
    }

    return true;
}

bool shadowvm_attach_to_process(ShadowVMContext* vm, HANDLE process) {
    if (!vm || !process) return false;

    // Install syscall hooks
    if (vm->features.intercept_syscalls) {
        if (!shadowvm_install_hooks(vm)) {
            return false;
        }
    }

    return true;
}

bool shadowvm_install_hooks(ShadowVMContext* vm) {
    if (!vm) return false;

    // Add vectored exception handler for syscall interception
    if (!AddVectoredExceptionHandler(1, syscall_handler)) {
        return false;
    }

    return true;
}

bool shadowvm_remove_hooks(ShadowVMContext* vm) {
    if (!vm) return false;

    // Remove vectored exception handler
    RemoveVectoredExceptionHandler(syscall_handler);

    return true;
}

void shadowvm_update_metrics(ShadowVMContext* vm) {
    if (!vm) return;

    // Update memory metrics
    if (vm->sandbox_memory) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(vm->sandbox_memory, &mbi, sizeof(mbi))) {
            vm->metrics.memory_used = mbi.RegionSize;
        }
    }
}

bool shadowvm_check_patterns(ShadowVMContext* vm, const uint8_t* data, size_t size) {
    if (!vm || !data) return false;

    // Check against known suspicious patterns
    for (size_t i = 0; i < sizeof(SUSPICIOUS_PATTERNS)/sizeof(SUSPICIOUS_PATTERNS[0]); i++) {
        if (pattern_match(data, size,
                          SUSPICIOUS_PATTERNS[i].pattern,
                          SUSPICIOUS_PATTERNS[i].size)) {
            vm->metrics.violations++;
            return true;
        }
    }

    return false;
}

static bool pattern_match(const uint8_t* data, size_t data_size,
                          const uint8_t* pattern, size_t pattern_size) {
    if (!data || !pattern || data_size < pattern_size) {
        return false;
    }

    // Simple Boyer-Moore-like pattern matching
    for (size_t i = 0; i <= data_size - pattern_size; i++) {
        bool match = true;
        for (size_t j = 0; j < pattern_size; j++) {
            if (data[i + j] != pattern[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            return true;
        }
    }

    return false;
}

// Syscall handler implementation
static LONG CALLBACK syscall_handler(EXCEPTION_POINTERS* exp) {
    if (exp->ExceptionRecord->ExceptionCode == EXCEPTION_PRIV_INSTRUCTION) {
        // Get syscall number from RAX register
        uint32_t syscall_num = (uint32_t)exp->ContextRecord->Rax;

        // Basic syscall filtering
        switch (syscall_num) {
            case 0x30: // Example: Block file operations
            case 0x31: // Example: Block network operations
            case 0x32: // Example: Block process creation
                return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

void shadowvm_cleanup(ShadowVMContext* vm) {
    if (!vm) return;

    // Free sandbox memory
    if (vm->sandbox_memory) {
        VirtualFree(vm->sandbox_memory, 0, MEM_RELEASE);
    }

    free(vm);
}