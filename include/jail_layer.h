#ifndef JAIL_LAYER_H
#define JAIL_LAYER_H

#include "security_types.h"

// Jail initialization and cleanup
JailContext* jail_init(const char* name, const char* root_path);
void jail_cleanup(JailContext* jail);

// Jail operations
bool jail_setup_filesystem(JailContext* jail);
bool jail_configure_network(JailContext* jail, const char* ip_address, uint32_t netmask);
bool jail_set_resource_limits(JailContext* jail, size_t max_memory, size_t max_processes);

// Process management
bool jail_start_process(JailContext* jail, HANDLE process);
bool jail_stop_process(JailContext* jail, HANDLE process);

// Monitoring
void jail_update_metrics(JailContext* jail);
bool jail_check_limits(JailContext* jail);

#endif // JAIL_LAYER_H