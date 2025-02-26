#ifndef SECURITY_SYSTEM_H

#define SECURITY_SYSTEM_H



#include "security_types.h"



// System initialization and cleanup

SecuritySystem* security_init(const char* log_path);

void security_cleanup(SecuritySystem* system);



// Layer management

bool add_jail_layer(SecuritySystem* system, const char* name, const char* root_path);

bool add_shadowvm_layer(SecuritySystem* system, size_t sandbox_size);



// Execution

bool security_execute(SecuritySystem* system, const char* command);



// Monitoring and control

bool check_security_violations(SecuritySystem* system, JailContext* jail, ShadowVMContext* vm);

void update_security_metrics(SecuritySystem* system);



#endif // SECURITY_SYSTEM_H