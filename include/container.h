#ifndef CONTAINER_H
#define CONTAINER_H

#include <windows.h>
#include <stdlib.h>
#include "resource_types.h"
#include "resource_monitor.h"

// Window container definitions
#define CONTAINER_CLASS_NAME   "ShadowVMContainer"
#define CONTAINER_TITLE        "ShadowVM Security Container"
#define CONTAINER_BORDER_WIDTH 4
#define CONTAINER_STATUS_HEIGHT 24
#define CONTAINER_INFO_HEIGHT  80
#define CONTAINER_REFRESH_ID   1001
#define CONTAINER_REFRESH_MS   250  // ms

// Status severity levels
typedef enum {
    SEVERITY_NORMAL = 0,
    SEVERITY_WARNING = 1,
    SEVERITY_ALERT = 2,
    SEVERITY_CRITICAL = 3
} SecuritySeverity;

// Status indicators
typedef struct {
    ULONGLONG file_ops;
    ULONGLONG network_ops;
    ULONGLONG memory_ops;
    ULONGLONG registry_ops;
    ULONGLONG process_ops;
    ULONGLONG blocked_ops;
    SecuritySeverity severity_level;
} SecurityStatus;

// Container context
typedef struct {
    HWND container_window;        // Main container window
    HWND child_window;            // Child application window
    HANDLE child_process;         // Child process handle
    DWORD child_process_id;       // Child process ID
    ResourceMonitor* monitor;     // Resource monitor
    SecurityStatus status;        // Security status
    HBRUSH border_brush;          // Border color brush
    BOOL security_violation;      // Flag for security violation
    RECT status_rect;             // Status bar rectangle
    HWND tooltip;                 // Tooltip for status
} ContainerContext;

// Container initialization
BOOL InitializeContainer(HINSTANCE hInstance);
ContainerContext* CreateContainer(HINSTANCE hInstance, ResourceMonitor* monitor);
BOOL LaunchProcessInContainer(ContainerContext* context, const char* command);

// Container operations
void UpdateContainerStatus(ContainerContext* context);
BOOL AddProcessToSecurityJob(ContainerContext* context);
void ResizeChildWindow(ContainerContext* context);

// Drawing functions
void DrawContainerBorder(HDC hdc, RECT* rect, HBRUSH brush);
void DrawStatusBar(HDC hdc, RECT* rect, SecurityStatus* status);
void DrawInfoPanel(HDC hdc, RECT* rect, SecurityStatus* status);
void DrawResourceGauge(HDC hdc, RECT* rect, int value, int max_value,
                       COLORREF low_color, COLORREF high_color);

// Security functions
BOOL DetectSecurityViolation(const ActivityRecord* activity);
SecuritySeverity CalculateSecuritySeverity(const SecurityStatus* status);
COLORREF GetSeverityColor(SecuritySeverity severity);

// Cleanup
void CleanupContainer(ContainerContext* context);

#endif // CONTAINER_H