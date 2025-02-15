// ShadowVM Core Implementation
// Windows-specific process-level virtual machine with syscall interception

#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <process.h>

// Resource types
#define RESOURCE_MEMORY    1
#define RESOURCE_FILE     2
#define RESOURCE_NETWORK  3
#define RESOURCE_PROCESS  4
#define RESOURCE_REGISTRY 5

// Access levels
#define ACCESS_NONE       0
#define ACCESS_READ       1
#define ACCESS_WRITE      2
#define ACCESS_EXECUTE    4
#define ACCESS_ALL        7

// Syscall numbers (Windows-specific)
#define SYSCALL_OPEN     0x30
#define SYSCALL_READ     0x31
#define SYSCALL_WRITE    0x32
#define SYSCALL_CONNECT  0x33
#define SYSCALL_PROCESS  0x34

// Forward declarations
struct ShadowVM;
struct SecurityConstraint;
struct SystemCallFilter;

// Resource monitoring structure
typedef struct ResourceUsage {
    uint32_t resource_type;
    size_t current_usage;
    size_t peak_usage;
    uint64_t access_count;
    FILETIME last_access;
    struct ResourceUsage* next;
} ResourceUsage;

// Enhanced constraint generator with pattern matching
typedef struct CodePattern {
    uint8_t* pattern;
    size_t pattern_size;
    uint32_t resource_type;
    uint32_t required_access;
} CodePattern;

// Resource monitor
typedef struct ResourceMonitor {
    ResourceUsage* usage_list;
    CRITICAL_SECTION lock;
    FILE* log_file;
    bool monitoring_enabled;
} ResourceMonitor;

// Syscall context for filtering
typedef struct SyscallContext {
    uint32_t syscall_number;
    void* params;
    bool allowed;
    char reason[256];
} SyscallContext;

// Resource limit structure
typedef struct ResourceLimit {
    uint32_t resource_type;
    size_t max_usage;
    uint64_t max_access_count;
} ResourceLimit;

// Pattern matching for code analysis
static const CodePattern KNOWN_PATTERNS[] = {
    // File access pattern
    {(uint8_t*)"\x68\x00\x00\x00\x00\xFF\x15", 7, RESOURCE_FILE, ACCESS_READ},
    // Network access pattern
    {(uint8_t*)"\x68\x02\x00\x00\x00\x68", 6, RESOURCE_NETWORK, ACCESS_READ | ACCESS_WRITE},
    // Process creation pattern
    {(uint8_t*)"\xFF\x75\x08\xFF\x75\x0C", 6, RESOURCE_PROCESS, ACCESS_ALL},
};

// Core VM structure
typedef struct ShadowVM {
    HANDLE process;
    void* sandbox_memory;
    size_t sandbox_size;
    struct SecurityConstraint* constraints;
    struct SystemCallFilter* syscall_filters;
    bool is_running;
} ShadowVM;

typedef struct PythonVM {
    char* python_path;
    char* script_path;
    PROCESS_INFORMATION process_info;
    SECURITY_ATTRIBUTES security_attr;
} PythonVM;

// Security constraint structure
typedef struct SecurityConstraint {
    uint32_t resource_type;
    uint32_t access_level;
    void* resource_handle;
    struct SecurityConstraint* next;
} SecurityConstraint;

// System call filter structure
typedef struct SystemCallFilter {
    uint32_t syscall_number;
    bool (*filter_func)(void* params);
    struct SystemCallFilter* next;
} SystemCallFilter;

// File access policy configuration
typedef struct FileAccessPolicy {
    char allowed_paths[10][MAX_PATH];
    char allowed_extensions[10][20];
    int num_allowed_paths;
    int num_allowed_extensions;
} FileAccessPolicy;

// Structure to hold script contents
typedef struct Script {
    uint8_t* data;
    size_t size;
} Script;

typedef enum ExecutableType {
    EXEC_TYPE_UNKNOWN,
    EXEC_TYPE_PYTHON,
    EXEC_TYPE_EXE,
    EXEC_TYPE_DLL
} ExecutableType;

typedef struct ExecutableInfo {
    ExecutableType type;
    char* path;
    char* args;
    bool requires_interpreter;
    union {
        PythonVM* python_vm;
        struct {
            PROCESS_INFORMATION proc_info;
            SECURITY_ATTRIBUTES sec_attr;
        } exe_info;
    };
} ExecutableInfo;

typedef struct ProcessActivity {
    HANDLE process;
    struct {
        uint64_t total_reads;
        uint64_t total_writes;
        uint64_t bytes_read;
        uint64_t bytes_written;
    } file_io;
    struct {
        uint64_t connection_attempts;
        uint64_t bytes_sent;
        uint64_t bytes_received;
    } network;
    struct {
        uint64_t ipc_attempts;
        uint64_t pipe_operations;
        uint64_t shared_memory_ops;
    } ipc;
} ProcessActivity;

// Initialize the CORE VM
ShadowVM* shadowvm_init(size_t sandbox_size) {
    ShadowVM* vm = (ShadowVM*)malloc(sizeof(ShadowVM));
    if (!vm) return NULL;

    // Initialize VM structure
    vm->sandbox_size = sandbox_size;
    vm->is_running = false;
    vm->constraints = NULL;
    vm->syscall_filters = NULL;

    // Allocate sandbox memory with proper protection
    vm->sandbox_memory = VirtualAlloc(
        NULL,
        sandbox_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!vm->sandbox_memory) {
        free(vm);
        return NULL;
    }

    return vm;
}

// Add security constraint
bool shadowvm_add_constraint(ShadowVM* vm, uint32_t resource_type,
    uint32_t access_level) {
    SecurityConstraint* constraint =
        (SecurityConstraint*)malloc(sizeof(SecurityConstraint));

    if (!constraint) return false;

    constraint->resource_type = resource_type;
    constraint->access_level = access_level;
    constraint->resource_handle = NULL;
    constraint->next = vm->constraints;

    vm->constraints = constraint;
    return true;
}

// Syscall interception setup
static LONG WINAPI vectored_handler(EXCEPTION_POINTERS* exp) {
    // Handle system call exceptions
    if (exp->ExceptionRecord->ExceptionCode == EXCEPTION_PRIV_INSTRUCTION) {
        // TODO: Implement syscall filtering logic
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// Set up syscall interception
bool shadowvm_setup_syscall_intercept(ShadowVM* vm) {
    // Add vectored exception handler for syscall interception
    AddVectoredExceptionHandler(1, vectored_handler);
    return true;
}

// Execute code in sandbox
bool shadowvm_execute(ShadowVM* vm, const uint8_t* code, size_t code_size) {
    if (!vm || !code || code_size > vm->sandbox_size) return false;

    // Copy code to sandbox memory
    memcpy(vm->sandbox_memory, code, code_size);

    // Set memory protection to execute-only
    DWORD old_protect;
    if (!VirtualProtect(vm->sandbox_memory, code_size,
        PAGE_EXECUTE_READ, &old_protect)) {
        return false;
    }

    vm->is_running = true;

    // Execute code in sandbox
    typedef void (*CodeFunc)();
    CodeFunc func = (CodeFunc)vm->sandbox_memory;

    __try {
        func();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        vm->is_running = false;
        return false;
    }

    vm->is_running = false;
    return true;
}

// Clean up VM resources
void shadowvm_cleanup(ShadowVM* vm) {
    if (!vm) return;

    // Free sandbox memory
    if (vm->sandbox_memory) {
        VirtualFree(vm->sandbox_memory, 0, MEM_RELEASE);
    }

    // Clean up constraints
    SecurityConstraint* curr_constraint = vm->constraints;
    while (curr_constraint) {
        SecurityConstraint* next = curr_constraint->next;
        free(curr_constraint);
        curr_constraint = next;
    }

    // Clean up syscall filters
    SystemCallFilter* curr_filter = vm->syscall_filters;
    while (curr_filter) {
        SystemCallFilter* next = curr_filter->next;
        free(curr_filter);
        curr_filter = next;
    }

    free(vm);
}

// Constraint generation system
typedef struct ConstraintGenerator {
    uint8_t* code;
    size_t code_size;
    SecurityConstraint* generated_constraints;
} ConstraintGenerator;

ConstraintGenerator* constraint_generator_init(const uint8_t* code,
    size_t code_size) {
    ConstraintGenerator* gen =
        (ConstraintGenerator*)malloc(sizeof(ConstraintGenerator));

    if (!gen) return NULL;

    gen->code = (uint8_t*)malloc(code_size);
    if (!gen->code) {
        free(gen);
        return NULL;
    }

    memcpy(gen->code, code, code_size);
    gen->code_size = code_size;
    gen->generated_constraints = NULL;

    return gen;
}

// Analyze code and generate constraints
bool constraint_generator_analyze(ConstraintGenerator* gen) {
    if (!gen) return false;

    // TODO: Implement actual code analysis
    // This is where static analysis would be implemented to identify:
    // - System call patterns
    // - Resource usage
    // - Memory access patterns
    // - API calls

    // add basic memory and file access constraints
    SecurityConstraint* mem_constraint =
        (SecurityConstraint*)malloc(sizeof(SecurityConstraint));
    if (mem_constraint) {
        mem_constraint->resource_type = 1; // Memory
        mem_constraint->access_level = 2; // Read/Execute
        mem_constraint->next = gen->generated_constraints;
        gen->generated_constraints = mem_constraint;
    }

    SecurityConstraint* file_constraint =
        (SecurityConstraint*)malloc(sizeof(SecurityConstraint));
    if (file_constraint) {
        file_constraint->resource_type = 2; // File
        file_constraint->access_level = 1; // Read only
        file_constraint->next = gen->generated_constraints;
        gen->generated_constraints = file_constraint;
    }

    return true;
}

void constraint_generator_cleanup(ConstraintGenerator* gen) {
    if (!gen) return;

    if (gen->code) {
        free(gen->code);
    }

    SecurityConstraint* curr = gen->generated_constraints;
    while (curr) {
        SecurityConstraint* next = curr->next;
        free(curr);
        curr = next;
    }

    free(gen);
}

// Initialize Python VM
PythonVM* python_vm_init(const char* script_path) {
    PythonVM* pvm = (PythonVM*)malloc(sizeof(PythonVM));
    if (!pvm) return NULL;

    // Find Python interpreter
    char python_path[MAX_PATH];
    // Assumes Python is in PATH
    strcpy(python_path, "python");

    pvm->python_path = _strdup(python_path);
    pvm->script_path = _strdup(script_path);

    ZeroMemory(&pvm->process_info, sizeof(PROCESS_INFORMATION));
    pvm->security_attr.nLength = sizeof(SECURITY_ATTRIBUTES);
    pvm->security_attr.bInheritHandle = TRUE;
    pvm->security_attr.lpSecurityDescriptor = NULL;

    return pvm;
}

// Function to show process isolation metrics
void show_process_isolation(HANDLE process) {
    PROCESS_MEMORY_COUNTERS_EX pmc;
    FILETIME creation_time, exit_time, kernel_time, user_time;

    printf("\n=== Process Isolation Metrics ===\n");

    if (GetProcessMemoryInfo(process, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
        printf("Private Memory Usage: %zu bytes\n", pmc.PrivateUsage);
        printf("Working Set Size: %zu bytes\n", pmc.WorkingSetSize);
    }
    else {
        printf("Failed to get process memory info: %lu\n", GetLastError());
    }

    // CPU isolation
    if (GetProcessTimes(process, &creation_time, &exit_time, &kernel_time, &user_time)) {
        SYSTEMTIME sys_time;
        FileTimeToSystemTime(&creation_time, &sys_time);
        printf("Process Start Time: %02d:%02d:%02d.%03d\n",
            sys_time.wHour, sys_time.wMinute, sys_time.wSecond, sys_time.wMilliseconds);
    }

    // Process boundaries
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(process));
    if (snapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 me32;
        me32.dwSize = sizeof(MODULEENTRY32);

        if (Module32First(snapshot, &me32)) {
            printf("\nProcess Memory Space:\n");
            printf("Base Address: 0x%p\n", me32.modBaseAddr);
            printf("Size: %u bytes\n", me32.modBaseSize);
        }
        CloseHandle(snapshot);
    }
}

// Execute Python script
bool python_execute(PythonVM* pvm) {
    if (!pvm) return false;

    STARTUPINFO si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    // Create command line
    char command_line[MAX_PATH * 2];
    snprintf(command_line, sizeof(command_line), "%s %s", pvm->python_path, pvm->script_path);

    // Get start time
    FILETIME start_time;
    GetSystemTimeAsFileTime(&start_time);

    // When creating the process, we need PROCESS_QUERY_INFORMATION rights
    if (!CreateProcess(NULL,   // No module name (use command line)
        command_line,
        &pvm->security_attr,
        &pvm->security_attr,
        TRUE,
        CREATE_NEW_CONSOLE | PROCESS_QUERY_INFORMATION,
        NULL,
        NULL,
        &si,
        &pvm->process_info))
    {
        printf("Failed to create Python process: %lu\n", GetLastError());
        return false;
    }

    printf("\n=== Process Creation Overhead ===\n");
    FILETIME current_time;
    GetSystemTimeAsFileTime(&current_time);
    ULARGE_INTEGER start_ul = { .LowPart = start_time.dwLowDateTime,
            .HighPart = start_time.dwHighDateTime };
    ULARGE_INTEGER current_ul = { .LowPart = current_time.dwLowDateTime,
            .HighPart = current_time.dwHighDateTime };
    printf("Process Creation Time: %llu microseconds\n",
        (current_ul.QuadPart - start_ul.QuadPart) / 10);

    // Show isolation metrics
    show_process_isolation(pvm->process_info.hProcess);

    // Wait for completion and measure total time
    DWORD start_tick = GetTickCount();
    WaitForSingleObject(pvm->process_info.hProcess, INFINITE);
    DWORD end_tick = GetTickCount();

    printf("\n=== Execution Summary ===\n");
    printf("Total Execution Time: %u ms\n", end_tick - start_tick);

    return true;
}

// Cleanup Python VM
void python_vm_cleanup(PythonVM* pvm) {
    if (!pvm) return;

    if (pvm->process_info.hProcess) {
        CloseHandle(pvm->process_info.hProcess);
    }
    if (pvm->process_info.hThread) {
        CloseHandle(pvm->process_info.hThread);
    }

    free(pvm->python_path);
    free(pvm->script_path);
    free(pvm);
}

// Initialize resource monitor
ResourceMonitor* monitor_init() {
    ResourceMonitor* monitor = (ResourceMonitor*)malloc(sizeof(ResourceMonitor));
    if (!monitor) return NULL;

    InitializeCriticalSection(&monitor->lock);
    monitor->usage_list = NULL;
    monitor->monitoring_enabled = true;

    // Open log file
    monitor->log_file = fopen("shadowvm_resource.log", "w");
    if (!monitor->log_file) {
        DeleteCriticalSection(&monitor->lock);
        free(monitor);
        return NULL;
    }

    return monitor;
}

// Log resource access
void monitor_log_access(ResourceMonitor* monitor, uint32_t resource_type,
    size_t usage_amount) {
    if (!monitor || !monitor->monitoring_enabled) return;

    EnterCriticalSection(&monitor->lock);

    // Find or create resource usage entry
    ResourceUsage* usage = monitor->usage_list;
    while (usage && usage->resource_type != resource_type) {
        usage = usage->next;
    }

    if (!usage) {
        usage = (ResourceUsage*)malloc(sizeof(ResourceUsage));
        if (usage) {
            usage->resource_type = resource_type;
            usage->current_usage = 0;
            usage->peak_usage = 0;
            usage->access_count = 0;
            GetSystemTimeAsFileTime(&usage->last_access);
            usage->next = monitor->usage_list;
            monitor->usage_list = usage;
        }
    }

    if (usage) {
        usage->current_usage += usage_amount;
        if (usage->current_usage > usage->peak_usage) {
            usage->peak_usage = usage->current_usage;
        }
        usage->access_count++;
        GetSystemTimeAsFileTime(&usage->last_access);

        if (monitor->log_file) {
            fprintf(monitor->log_file,
                "Resource access - Type: %u, Amount: %zu, Total: %zu\n",
                resource_type, usage_amount, usage->current_usage);
            fflush(monitor->log_file);
        }
    }

    LeaveCriticalSection(&monitor->lock);
}

// constraint analysis
bool analyze_code_patterns(const uint8_t* code, size_t code_size,
    SecurityConstraint** constraints) {
    for (size_t i = 0; i < code_size; i++) {
        // Check each known pattern
        for (size_t p = 0; p < sizeof(KNOWN_PATTERNS) / sizeof(CodePattern); p++) {
            const CodePattern* pattern = &KNOWN_PATTERNS[p];

            if (i + pattern->pattern_size <= code_size) {
                if (memcmp(code + i, pattern->pattern, pattern->pattern_size) == 0) {
                    // Pattern matched - create constraint
                    SecurityConstraint* constraint =
                        (SecurityConstraint*)malloc(sizeof(SecurityConstraint));

                    if (constraint) {
                        constraint->resource_type = pattern->resource_type;
                        constraint->access_level = pattern->required_access;
                        constraint->next = *constraints;
                        *constraints = constraint;
                    }
                }
            }
        }
    }
    return true;
}

// Syscall filtering implementation
bool filter_syscall(SyscallContext* context) {
    switch (context->syscall_number) {
        case SYSCALL_OPEN: {
            // Check file access
            char* filename = (char*)context->params;
            // Deny access to sensitive paths
            if (strstr(filename, "\\windows\\") ||
                strstr(filename, "\\system32\\")) {
                context->allowed = false;
                snprintf(context->reason, sizeof(context->reason),
                    "Access to system directories denied");
                return false;
            }
            break;
        }

        case SYSCALL_CONNECT: {
            // Check network connections
            struct {
                uint32_t ip;
                uint16_t port;
            }*conn_info = (void*)context->params;

            // Deny connections to privileged ports
            if (conn_info->port < 1024) {
                context->allowed = false;
                snprintf(context->reason, sizeof(context->reason),
                    "Access to privileged ports denied");
                return false;
            }
            break;
        }

        case SYSCALL_PROCESS: {
            // Deny process creation by default
            context->allowed = false;
            snprintf(context->reason, sizeof(context->reason),
                "Process creation not allowed");
            return false;
        }
    }

    context->allowed = true;
    return true;
}

// Check resource limits
bool check_resource_limits(ResourceMonitor* monitor, ResourceLimit* limits,
    size_t limit_count) {
    if (!monitor) return false;

    EnterCriticalSection(&monitor->lock);
    bool within_limits = true;

    ResourceUsage* usage = monitor->usage_list;
    while (usage && within_limits) {
        for (size_t i = 0; i < limit_count; i++) {
            if (usage->resource_type == limits[i].resource_type) {
                if (usage->current_usage > limits[i].max_usage ||
                    usage->access_count > limits[i].max_access_count) {
                    within_limits = false;
                    break;
                }
            }
        }
        usage = usage->next;
    }

    LeaveCriticalSection(&monitor->lock);
    return within_limits;
}

// Initialize default file access policy
FileAccessPolicy* init_default_policy() {
    FileAccessPolicy* policy = (FileAccessPolicy*)malloc(sizeof(FileAccessPolicy));
    if (!policy) return NULL;

    policy->num_allowed_paths = 0;
    policy->num_allowed_extensions = 0;

    // Add current directory to allowed paths
    char current_dir[MAX_PATH];
    GetCurrentDirectory(MAX_PATH, current_dir);
    strcpy(policy->allowed_paths[policy->num_allowed_paths++], current_dir);

    // Add allowed extensions
    strcpy(policy->allowed_extensions[policy->num_allowed_extensions++], ".py");
    strcpy(policy->allowed_extensions[policy->num_allowed_extensions++], ".txt");
    strcpy(policy->allowed_extensions[policy->num_allowed_extensions++], ".json");

    return policy;
}

// file path checking
bool is_path_allowed(FileAccessPolicy* policy, const char* filepath) {
    char normalized_path[MAX_PATH];
    char canonical_path[MAX_PATH];

    // Get the full path
    if (!GetFullPathName(filepath, MAX_PATH, normalized_path, NULL)) {
        return false;
    }

    // Convert to canonical path (resolve any ../ etc)
    if (!GetLongPathName(normalized_path, canonical_path, MAX_PATH)) {
        strcpy(canonical_path, normalized_path);
    }

    // Check against system directories
    if (strstr(canonical_path, "\\windows\\") ||
        strstr(canonical_path, "\\system32\\")) {
        // Special case: allow python runtime if needed
        if (strstr(canonical_path, "\\python3") ||
            strstr(canonical_path, "\\Scripts\\python.exe")) {
            return true;
        }
        return false;
    }

    // Check if path is under any allowed directory
    for (int i = 0; i < policy->num_allowed_paths; i++) {
        if (strstr(canonical_path, policy->allowed_paths[i]) == canonical_path) {
            // Check file extension
            char* ext = strrchr(canonical_path, '.');
            if (ext) {
                for (int j = 0; j < policy->num_allowed_extensions; j++) {
                    if (_stricmp(ext, policy->allowed_extensions[j]) == 0) {
                        return true;
                    }
                }
            }
        }
    }

    return false;
}

// syscall filter with policy
bool filter_file_syscall(SyscallContext* context, FileAccessPolicy* policy) {
    if (context->syscall_number == SYSCALL_OPEN) {
        char* filename = (char*)context->params;

        if (!is_path_allowed(policy, filename)) {
            context->allowed = false;
            snprintf(context->reason, sizeof(context->reason),
                "Access denied: Path not allowed - %s", filename);
            return false;
        }

        // Additional access checks to be added here

        context->allowed = true;
        return true;
    }

    return true;
}

// Debug logging for file access attempts
void log_file_access_attempt(const char* filepath, bool allowed,
    const char* reason) {
    FILE* log_file = fopen("shadowvm_file_access.log", "a");
    if (log_file) {
        SYSTEMTIME st;
        GetLocalTime(&st);

        fprintf(log_file, "[%02d:%02d:%02d.%03d] File access %s: %s\n",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            allowed ? "ALLOWED" : "DENIED",
            filepath);

        if (!allowed && reason) {
            fprintf(log_file, "Reason: %s\n", reason);
        }

        fprintf(log_file, "---\n");
        fclose(log_file);
    }
}

// Load script from file
Script* load_script(const char* filename) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        printf("Failed to open script file: %s\n", filename);
        return NULL;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate memory for script data
    Script* script = (Script*)malloc(sizeof(Script));
    if (!script) {
        fclose(file);
        return NULL;
    }

    script->data = (uint8_t*)malloc(file_size);
    if (!script->data) {
        free(script);
        fclose(file);
        return NULL;
    }

    script->size = file_size;

    // Read file contents
    size_t read_size = fread(script->data, 1, file_size, file);
    fclose(file);

    if (read_size != file_size) {
        free(script->data);
        free(script);
        return NULL;
    }

    return script;
}

// Clean up script resources
void script_cleanup(Script* script) {
    if (script) {
        if (script->data) {
            free(script->data);
        }
        free(script);
    }
}

// Execute script in VM
bool execute_script(ShadowVM* vm, Script* script) {
    if (!vm || !script) {
        return false;
    }

    // Set up constraints for script execution
    shadowvm_add_constraint(vm, RESOURCE_MEMORY, ACCESS_READ | ACCESS_WRITE | ACCESS_EXECUTE);
    shadowvm_add_constraint(vm, RESOURCE_FILE, ACCESS_READ);

    // Set up syscall interception
    if (!shadowvm_setup_syscall_intercept(vm)) {
        printf("Failed to set up syscall interception\n");
        return false;
    }

    // Execute the script in sandbox
    bool result = shadowvm_execute(vm, script->data, script->size);

    if (!result) {
        printf("Script execution failed\n");
    }

    return result;
}

// Clean up resource monitor
void monitor_cleanup(ResourceMonitor* monitor) {
    if (!monitor) return;

    // Ensure thread safety while cleaning up
    EnterCriticalSection(&monitor->lock);

    // Close log file if open
    if (monitor->log_file) {
        fclose(monitor->log_file);
        monitor->log_file = NULL;
    }

    // Free all resource usage entries
    ResourceUsage* current = monitor->usage_list;
    while (current) {
        ResourceUsage* next = current->next;
        free(current);
        current = next;
    }
    monitor->usage_list = NULL;

    // Release the critical section
    LeaveCriticalSection(&monitor->lock);
    DeleteCriticalSection(&monitor->lock);

    // Finally free the monitor itself
    free(monitor);
}

// Function to determine executable type
ExecutableType get_executable_type(const char* path) {
    const char* ext = strrchr(path, '.');
    if (!ext) return EXEC_TYPE_UNKNOWN;

    if (_stricmp(ext, ".py") == 0) return EXEC_TYPE_PYTHON;
    if (_stricmp(ext, ".exe") == 0) return EXEC_TYPE_EXE;
    if (_stricmp(ext, ".dll") == 0) return EXEC_TYPE_DLL;

    return EXEC_TYPE_UNKNOWN;
}

// Initialize executable environment
ExecutableInfo* exec_init(const char* path, const char* args) {
    ExecutableInfo* info = (ExecutableInfo*)malloc(sizeof(ExecutableInfo));
    if (!info) return NULL;

    info->type = get_executable_type(path);
    info->path = _strdup(path);
    info->args = args ? _strdup(args) : NULL;

    switch (info->type) {
    case EXEC_TYPE_PYTHON:
        info->requires_interpreter = true;
        info->python_vm = python_vm_init(path);
        if (!info->python_vm) {
            free(info->path);
            free(info->args);
            free(info);
            return NULL;
        }
        break;

    case EXEC_TYPE_EXE:
        info->requires_interpreter = false;
        ZeroMemory(&info->exe_info.proc_info, sizeof(PROCESS_INFORMATION));
        info->exe_info.sec_attr.nLength = sizeof(SECURITY_ATTRIBUTES);
        info->exe_info.sec_attr.bInheritHandle = TRUE;
        info->exe_info.sec_attr.lpSecurityDescriptor = NULL;
        break;

        // TODO: Add Ruby, Lua, Bash, Batch, Powershell, Node.js and other scripting languages
    default:
        free(info->path);
        free(info->args);
        free(info);
        return NULL;
    }

    return info;
}

// Execute within sandbox
bool exec_run(ExecutableInfo* info) {
    if (!info) return false;

    switch (info->type) {
    case EXEC_TYPE_PYTHON:
        return python_execute(info->python_vm);

    case EXEC_TYPE_EXE: {
        STARTUPINFO si;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);

        // Prepare command line
        char command_line[MAX_PATH * 2];
        if (info->args) {
            snprintf(command_line, sizeof(command_line), "\"%s\" %s",
                info->path, info->args);
        }
        else {
            snprintf(command_line, sizeof(command_line), "\"%s\"", info->path);
        }

        // Create sandboxed process
        if (!CreateProcess(NULL,
            command_line,
            &info->exe_info.sec_attr,
            &info->exe_info.sec_attr,
            TRUE,
            CREATE_NEW_CONSOLE | PROCESS_QUERY_INFORMATION,
            NULL,
            NULL,
            &si,
            &info->exe_info.proc_info))
        {
            printf("Failed to create process: %lu\n", GetLastError());
            return false;
        }

        // Show process isolation metrics
        show_process_isolation(info->exe_info.proc_info.hProcess);

        // Wait for completion
        WaitForSingleObject(info->exe_info.proc_info.hProcess, INFINITE);

        DWORD exit_code;
        GetExitCodeProcess(info->exe_info.proc_info.hProcess, &exit_code);
        return exit_code == 0;
    }

    default:
        return false;
    }
}

// Cleanup
void exec_cleanup(ExecutableInfo* info) {
    if (!info) return;

    switch (info->type) {
    case EXEC_TYPE_PYTHON:
        if (info->python_vm) {
            python_vm_cleanup(info->python_vm);
        }
        break;

    case EXEC_TYPE_EXE:
        if (info->exe_info.proc_info.hProcess) {
            CloseHandle(info->exe_info.proc_info.hProcess);
        }
        if (info->exe_info.proc_info.hThread) {
            CloseHandle(info->exe_info.proc_info.hThread);
        }
        break;
    }

    free(info->path);
    free(info->args);
    free(info);
}

// Initialize activity monitoring
ProcessActivity* init_activity_monitor(HANDLE process) {
    ProcessActivity* activity = (ProcessActivity*)malloc(sizeof(ProcessActivity));
    if (!activity) return NULL;

    memset(activity, 0, sizeof(ProcessActivity));
    activity->process = process;

    return activity;
}

// Monitor process activity (called periodically)
void update_activity_stats(ProcessActivity* activity) {
    if (!activity) return;

    IO_COUNTERS io_counters;
    if (GetProcessIoCounters(activity->process, &io_counters)) {
        activity->file_io.total_reads = io_counters.ReadOperationCount;
        activity->file_io.total_writes = io_counters.WriteOperationCount;
        activity->file_io.bytes_read = io_counters.ReadTransferCount;
        activity->file_io.bytes_written = io_counters.WriteTransferCount;
    }

    printf("\n=== Process Activity Update ===\n");
    printf("File I/O:\n");
    printf("  Reads:  %llu operations, %llu bytes\n",
        activity->file_io.total_reads, activity->file_io.bytes_read);
    printf("  Writes: %llu operations, %llu bytes\n",
        activity->file_io.total_writes, activity->file_io.bytes_written);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <executable_or_script> [args...]\n", argv[0]);
        return 1;
    }

    // Combine remaining arguments
    char args[1024] = { 0 };
    if (argc > 2) {
        for (int i = 2; i < argc; i++) {
            strcat(args, argv[i]);
            strcat(args, " ");
        }
    }

    // Initialize executable environment
    ExecutableInfo* exec = exec_init(argv[1], args[0] ? args : NULL);
    if (!exec) {
        printf("Failed to initialize executable environment\n");
        return 1;
    }

    // Execute in sandbox
    printf("Executing in sandbox: %s\n", argv[1]);

    // Start monitoring before execution
    ProcessActivity* activity = NULL;
    if (exec->type == EXEC_TYPE_EXE) {
        if (exec_run(exec)) {
            // Initialize activity monitor after process is created
            activity = init_activity_monitor(exec->exe_info.proc_info.hProcess);
            if (activity) {
                // Initial stats
                update_activity_stats(activity);

                // Monitor loop
                while (WaitForSingleObject(exec->exe_info.proc_info.hProcess, 1000) == WAIT_TIMEOUT) {
                    update_activity_stats(activity);
                }

                // Final stats
                update_activity_stats(activity);

                // Cleanup activity monitor
                free(activity);
            }
            printf("Execution completed successfully\n");
        }
        else {
            printf("Execution failed\n");
        }
    }
    else {
        // Handle non-EXE files (Python scripts, etc.)
        if (!exec_run(exec)) {
            printf("Execution failed\n");
        }
        else {
            printf("Execution completed successfully\n");
        }
    }

    // Cleanup
    exec_cleanup(exec);

    return 0;
}