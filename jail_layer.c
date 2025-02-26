#include "jail_layer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Private function declarations
static bool setup_job_object(JailContext* jail);
static bool create_jail_directories(const char* root_path);

JailContext* jail_init(const char* name, const char* root_path) {
    if (!name || !root_path) return NULL;

    JailContext* jail = (JailContext*)calloc(1, sizeof(JailContext));
    if (!jail) return NULL;

    // Copy name and path
    jail->name = _strdup(name);
    jail->root_path = _strdup(root_path);
    if (!jail->name || !jail->root_path) {
        jail_cleanup(jail);
        return NULL;
    }

    // Set default policy
    jail->policy.allow_network = false;
    jail->policy.allow_files = true;
    jail->policy.allow_registry = false;
    jail->policy.max_processes = 50;
    jail->policy.memory_limit = 256 * 1024 * 1024;  // 256 MB

    // Initialize job object
    if (!setup_job_object(jail)) {
        jail_cleanup(jail);
        return NULL;
    }

    // Create jail filesystem structure
    if (!create_jail_directories(root_path)) {
        jail_cleanup(jail);
        return NULL;
    }

    return jail;
}

bool jail_setup_filesystem(JailContext* jail) {
    if (!jail) return false;

    // Create basic jail directory structure
    const char* dirs[] = {
            "\\bin",
            "\\dev",
            "\\etc",
            "\\home",
            "\\lib",
            "\\usr",
            "\\var",
            "\\tmp"
    };

    for (int i = 0; i < sizeof(dirs)/sizeof(char*); i++) {
        char path[MAX_PATH];
        snprintf(path, sizeof(path), "%s%s", jail->root_path, dirs[i]);

        if (!CreateDirectory(path, NULL)) {
            if (GetLastError() != ERROR_ALREADY_EXISTS) {
                return false;
            }
        }
    }

    return true;
}

bool jail_configure_network(JailContext* jail, const char* ip_address, uint32_t netmask) {
    if (!jail) return false;

    // Network configuration would go here
    // This is a placeholder as Windows doesn't support network namespaces like FreeBSD

    jail->policy.allow_network = true;
    return true;
}

bool jail_set_resource_limits(JailContext* jail, size_t max_memory, size_t max_processes) {
    if (!jail) return false;

    jail->policy.memory_limit = max_memory;
    jail->policy.max_processes = max_processes;

    // Update job object limits
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    limits.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
            JOB_OBJECT_LIMIT_JOB_MEMORY |
            JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;

    limits.BasicLimitInformation.ActiveProcessLimit = max_processes;
    limits.JobMemoryLimit = max_memory;

    return SetInformationJobObject(
            jail->job_object,
            JobObjectExtendedLimitInformation,
            &limits,
            sizeof(limits)
    );
}

bool jail_start_process(JailContext* jail, HANDLE process) {
    if (!jail || !process) return false;

    // Assign process to job object
    if (!AssignProcessToJobObject(jail->job_object, process)) {
        return false;
    }

    // Update jail state
    jail->state.active = true;
    jail->state.process_count++;
    GetSystemTimeAsFileTime(&jail->state.start_time);

    return true;
}

bool jail_stop_process(JailContext* jail, HANDLE process) {
    if (!jail || !process) return false;

    // Note: Windows automatically removes processes from job objects on termination

    if (jail->state.process_count > 0) {
        jail->state.process_count--;
    }

    if (jail->state.process_count == 0) {
        jail->state.active = false;
    }

    return true;
}

void jail_update_metrics(JailContext* jail) {
    if (!jail) return;

    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info;
    if (QueryInformationJobObject(
            jail->job_object,
            JobObjectBasicAccountingInformation,
            &info,
            sizeof(info),
            NULL))
    {
        jail->state.process_count = info.ActiveProcesses;
    }
}

bool jail_check_limits(JailContext* jail) {
    if (!jail) return false;

    // Get process count
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting_info;
    if (!QueryInformationJobObject(
            jail->job_object,
            JobObjectBasicAccountingInformation,
            &accounting_info,
            sizeof(accounting_info),
            NULL))
    {
        return false;
    }

    // Get memory usage
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limit_info;
    if (!QueryInformationJobObject(
            jail->job_object,
            JobObjectExtendedLimitInformation,
            &limit_info,
            sizeof(limit_info),
            NULL))
    {
        return false;
    }

    // Check process count
    if (accounting_info.ActiveProcesses > jail->policy.max_processes) {
        return false;
    }

    // Check memory usage
    if (limit_info.PeakJobMemoryUsed > jail->policy.memory_limit) {
        return false;
    }

    return true;
}

void jail_cleanup(JailContext* jail) {
    if (!jail) return;

    if (jail->job_object) {
        CloseHandle(jail->job_object);
    }

    free(jail->name);
    free(jail->root_path);
    free(jail);
}

// Private functions
static bool setup_job_object(JailContext* jail) {
    // Create job object
    jail->job_object = CreateJobObject(NULL, jail->name);
    if (!jail->job_object) {
        return false;
    }

    // Set basic limits
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    limits.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
            JOB_OBJECT_LIMIT_JOB_MEMORY |
            JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;

    limits.BasicLimitInformation.ActiveProcessLimit = jail->policy.max_processes;
    limits.JobMemoryLimit = jail->policy.memory_limit;

    return SetInformationJobObject(
            jail->job_object,
            JobObjectExtendedLimitInformation,
            &limits,
            sizeof(limits)
    );
}

static bool create_jail_directories(const char* root_path) {
    // Create root directory if it doesn't exist
    if (!CreateDirectory(root_path, NULL)) {
        if (GetLastError() != ERROR_ALREADY_EXISTS) {
            return false;
        }
    }

    return true;
}