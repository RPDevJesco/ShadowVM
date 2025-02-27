#include "container.h"
#include <stdio.h>
#include <psapi.h>

// Global container context
static ContainerContext* g_context = NULL;

// Forward declarations for internal functions
static LRESULT CALLBACK ContainerWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
static BOOL CALLBACK FindProcessWindowCallback(HWND hwnd, LPARAM lParam);
static HWND FindProcessMainWindow(DWORD process_id);
static SIZE_T GetProcessMemoryUsage(HANDLE process);

// Initialize the container system
BOOL InitializeContainer(HINSTANCE hInstance) {
    WNDCLASSEX wcex = {0};

    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = ContainerWndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName = NULL;
    wcex.lpszClassName = CONTAINER_CLASS_NAME;
    wcex.hIconSm = LoadIcon(NULL, IDI_APPLICATION);

    return RegisterClassEx(&wcex);
}

// Create a new container
ContainerContext* CreateContainer(HINSTANCE hInstance, ResourceMonitor* monitor) {
    // Allocate context
    ContainerContext* context = (ContainerContext*)calloc(1, sizeof(ContainerContext));
    if (!context) return NULL;

    // Store monitor
    context->monitor = monitor;

    // Get screen dimensions for initial size
    int screen_width = GetSystemMetrics(SM_CXSCREEN);
    int screen_height = GetSystemMetrics(SM_CYSCREEN);

    // Create window at 80% of screen size, centered
    int window_width = (int)(screen_width * 0.8);
    int window_height = (int)(screen_height * 0.8);
    int window_x = (screen_width - window_width) / 2;
    int window_y = (screen_height - window_height) / 2;

    // Create the container window
    context->container_window = CreateWindowEx(
            0,
            CONTAINER_CLASS_NAME,
            CONTAINER_TITLE,
            WS_OVERLAPPEDWINDOW,
            window_x, window_y,
            window_width, window_height,
            NULL, NULL, hInstance, NULL
    );

    if (!context->container_window) {
        free(context);
        return NULL;
    }

    // Set the context in the window's user data
    SetWindowLongPtr(context->container_window, GWLP_USERDATA, (LONG_PTR)context);

    // Create default border brush (green)
    context->border_brush = CreateSolidBrush(RGB(0, 128, 0));

    // Set up status rect
    RECT client_rect;
    GetClientRect(context->container_window, &client_rect);
    context->status_rect.left = 0;
    context->status_rect.top = 0;
    context->status_rect.right = client_rect.right;
    context->status_rect.bottom = CONTAINER_STATUS_HEIGHT;

    // Set refresh timer
    SetTimer(context->container_window, CONTAINER_REFRESH_ID, CONTAINER_REFRESH_MS, NULL);

    // Show the window
    ShowWindow(context->container_window, SW_SHOW);
    UpdateWindow(context->container_window);

    // Store the global context
    g_context = context;

    return context;
}

// Launch a process inside the container
BOOL LaunchProcessInContainer(ContainerContext* context, const char* command) {
    if (!context || !command) return FALSE;

    // Create process in suspended state
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    // Create with visible window
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW;

    if (!CreateProcess(
            NULL,               // No module name (use command line)
            (LPSTR)command,     // Command line
            NULL,               // Process handle not inheritable
            NULL,               // Thread handle not inheritable
            FALSE,              // Set handle inheritance to FALSE
            CREATE_SUSPENDED,   // Create suspended
            NULL,               // Use parent's environment block
            NULL,               // Use parent's starting directory
            &si,                // Pointer to STARTUPINFO structure
            &pi)                // Pointer to PROCESS_INFORMATION structure
            ) {
        return FALSE;
    }

    // Store process handle and ID
    context->child_process = pi.hProcess;
    context->child_process_id = pi.dwProcessId;

    // Add process to job object
    AddProcessToSecurityJob(context);

    // Resume the process to let it create its window
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);

    // Wait for the process to create its main window
    Sleep(500);  // Small delay to let the window be created

    // Find the main window of the process
    context->child_window = FindProcessMainWindow(context->child_process_id);

    if (!context->child_window) {
        // Try again with a longer wait
        for (int i = 0; i < 10 && !context->child_window; i++) {
            Sleep(100);  // Wait more
            context->child_window = FindProcessMainWindow(context->child_process_id);
        }
    }

    if (!context->child_window) {
        char msg[256];
        sprintf(msg, "Could not find window for process ID %lu. "
                     "The application will run but may not be contained properly.",
                context->child_process_id);
        MessageBox(context->container_window, msg, "ShadowVM Warning",
                   MB_OK | MB_ICONWARNING);

        // We'll continue even without a window, as the process monitoring still works
        return TRUE;
    }

    // Modify child window style to remove borders
    LONG style = GetWindowLong(context->child_window, GWL_STYLE);
    SetWindowLong(context->child_window, GWL_STYLE, style & ~WS_POPUP & ~WS_CAPTION & ~WS_THICKFRAME);

    // Set parent
    SetParent(context->child_window, context->container_window);

    // Adjust window size
    ResizeChildWindow(context);

    return TRUE;
}

// Add a process to a job object with security restrictions
BOOL AddProcessToSecurityJob(ContainerContext* context) {
    if (!context || !context->child_process) return FALSE;

    HANDLE job = CreateJobObject(NULL, NULL);
    if (!job) {
        return FALSE;
    }

    // Configure job to kill child processes when job is closed
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_info = {0};
    job_info.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
            JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;

    // Set memory limit (256MB)
    job_info.JobMemoryLimit = 256 * 1024 * 1024;
    job_info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;

    // Set process count limit
    job_info.BasicLimitInformation.ActiveProcessLimit = 10;
    job_info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    // Set memory limit (256MB)
    job_info.JobMemoryLimit = 256 * 1024 * 1024;
    job_info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;

    // Set process count limit
    job_info.BasicLimitInformation.ActiveProcessLimit = 10;
    job_info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;

    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                 &job_info, sizeof(job_info))) {
        CloseHandle(job);
        return FALSE;
    }

    // Configure UI restrictions
    JOBOBJECT_BASIC_UI_RESTRICTIONS ui_restrictions = {0};
    ui_restrictions.UIRestrictionsClass =
            JOB_OBJECT_UILIMIT_DESKTOP |
            JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
            JOB_OBJECT_UILIMIT_EXITWINDOWS |
            JOB_OBJECT_UILIMIT_GLOBALATOMS |
            JOB_OBJECT_UILIMIT_HANDLES |
            JOB_OBJECT_UILIMIT_READCLIPBOARD |
            JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS |
            JOB_OBJECT_UILIMIT_WRITECLIPBOARD;

    if (!SetInformationJobObject(job, JobObjectBasicUIRestrictions,
                                 &ui_restrictions, sizeof(ui_restrictions))) {
        CloseHandle(job);
        return FALSE;
    }

    // Assign process to job
    if (!AssignProcessToJobObject(job, context->child_process)) {
        CloseHandle(job);
        return FALSE;
    }

    // We intentionally don't close the job handle so the job stays alive
    return TRUE;
}

// Resize the child window to fit the container
void ResizeChildWindow(ContainerContext* context) {
    if (!context || !context->container_window || !context->child_window)
        return;

    // Get container client area
    RECT client_rect;
    GetClientRect(context->container_window, &client_rect);

    // Calculate content area (excluding border, status bar, and info panel)
    int content_x = CONTAINER_BORDER_WIDTH;
    int content_y = CONTAINER_BORDER_WIDTH + CONTAINER_STATUS_HEIGHT;
    int content_width = client_rect.right - (CONTAINER_BORDER_WIDTH * 2);
    int content_height = client_rect.bottom - CONTAINER_BORDER_WIDTH -
                         CONTAINER_STATUS_HEIGHT - CONTAINER_INFO_HEIGHT;

    // Move and resize child window
    SetWindowPos(context->child_window, NULL,
                 content_x, content_y,
                 content_width, content_height,
                 SWP_NOZORDER);
}

// Update security status information
void UpdateContainerStatus(ContainerContext* context) {
    if (!context || !context->monitor) return;

    // Update status based on monitor statistics
    context->status.file_ops = context->monitor->stats.total_file_ops;
    context->status.network_ops = context->monitor->stats.total_network_ops;
    context->status.memory_ops = context->monitor->stats.total_memory_ops;
    context->status.registry_ops = context->monitor->stats.total_registry_ops;
    context->status.process_ops = context->monitor->stats.total_process_ops;
    context->status.blocked_ops = context->monitor->stats.total_blocked_ops;

    // Calculate overall severity
    context->status.severity_level = CalculateSecuritySeverity(&context->status);

    // Update border color based on severity
    if (context->border_brush) {
        DeleteObject(context->border_brush);
    }

    context->border_brush = CreateSolidBrush(GetSeverityColor(context->status.severity_level));

    // Check if child process is still running
    if (context->child_process) {
        DWORD exit_code = 0;
        if (GetExitCodeProcess(context->child_process, &exit_code)) {
            if (exit_code != STILL_ACTIVE) {
                // Process has exited
                CloseHandle(context->child_process);
                context->child_process = NULL;
                context->child_process_id = 0;

                // Post message to notify about process termination
                PostMessage(context->container_window, WM_USER + 100, exit_code, 0);
            }
        }
    }

    // Redraw status area
    if (context->container_window) {
        InvalidateRect(context->container_window, &context->status_rect, FALSE);
    }
}

// Calculate security severity based on monitored activities
SecuritySeverity CalculateSecuritySeverity(const SecurityStatus* status) {
    if (!status) return SEVERITY_NORMAL;

    // Start with normal severity
    SecuritySeverity severity = SEVERITY_NORMAL;

    // Check thresholds for different activities
    if (status->network_ops > 50) {
        severity = max(severity, SEVERITY_WARNING);
    }

    if (status->file_ops > 500) {
        severity = max(severity, SEVERITY_WARNING);
    }

    if (status->blocked_ops > 0) {
        severity = max(severity, SEVERITY_ALERT);
    }

    // If security violation detected, set to critical
    if (status->blocked_ops > 10) {
        severity = SEVERITY_CRITICAL;
    }

    return severity;
}

// Get color based on security severity
COLORREF GetSeverityColor(SecuritySeverity severity) {
    switch (severity) {
        case SEVERITY_NORMAL:
            return RGB(0, 128, 0);     // Green
        case SEVERITY_WARNING:
            return RGB(255, 165, 0);   // Orange
        case SEVERITY_ALERT:
            return RGB(255, 0, 0);     // Red
        case SEVERITY_CRITICAL:
            return RGB(139, 0, 0);     // Dark Red
        default:
            return RGB(0, 128, 0);     // Default Green
    }
}

// Draw the container border
void DrawContainerBorder(HDC hdc, RECT* rect, HBRUSH brush) {
    if (!hdc || !rect) return;

    HBRUSH border_brush = brush ? brush : GetStockObject(DC_BRUSH);
    RECT border_rect = *rect;

    // Draw multiple rectangles for thicker border
    for (int i = 0; i < CONTAINER_BORDER_WIDTH; i++) {
        FrameRect(hdc, &border_rect, border_brush);
        InflateRect(&border_rect, -1, -1);
    }
}

// Draw the status bar
void DrawStatusBar(HDC hdc, RECT* rect, SecurityStatus* status) {
    if (!hdc || !rect || !status) return;

    // Fill background with severity color
    COLORREF bg_color = GetSeverityColor(status->severity_level);
    HBRUSH bg_brush = CreateSolidBrush(bg_color);
    FillRect(hdc, rect, bg_brush);
    DeleteObject(bg_brush);

    // Setup text properties
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, RGB(255, 255, 255));
    HFONT font = CreateFont(16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                            DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
    HFONT old_font = (HFONT)SelectObject(hdc, font);

    // Draw status text
    char status_text[256];
    char severity_text[16] = "NORMAL";

    switch (status->severity_level) {
        case SEVERITY_NORMAL:  strcpy(severity_text, "NORMAL"); break;
        case SEVERITY_WARNING: strcpy(severity_text, "WARNING"); break;
        case SEVERITY_ALERT:   strcpy(severity_text, "ALERT"); break;
        case SEVERITY_CRITICAL: strcpy(severity_text, "CRITICAL"); break;
    }

    sprintf(status_text, " ShadowVM Security Monitor | Status: %s | Blocked: %llu",
            severity_text, status->blocked_ops);

    RECT text_rect = *rect;
    DrawText(hdc, status_text, -1, &text_rect, DT_VCENTER | DT_SINGLELINE);

    // Draw process info
    char proc_text[64];
    if (g_context && g_context->child_process_id) {
        sprintf(proc_text, "PID: %lu ", g_context->child_process_id);
    } else {
        strcpy(proc_text, "No Process ");
    }

    RECT proc_rect = *rect;
    proc_rect.left = proc_rect.right - 100;
    DrawText(hdc, proc_text, -1, &proc_rect, DT_VCENTER | DT_SINGLELINE | DT_RIGHT);

    // Cleanup
    SelectObject(hdc, old_font);
    DeleteObject(font);
}

// Draw the information panel
void DrawInfoPanel(HDC hdc, RECT* rect, SecurityStatus* status) {
    if (!hdc || !rect || !status) return;

    // Fill background
    HBRUSH bg_brush = CreateSolidBrush(RGB(240, 240, 240));
    FillRect(hdc, rect, bg_brush);
    DeleteObject(bg_brush);

    // Draw border
    HPEN border_pen = CreatePen(PS_SOLID, 1, RGB(200, 200, 200));
    HPEN old_pen = (HPEN)SelectObject(hdc, border_pen);
    Rectangle(hdc, rect->left, rect->top, rect->right, rect->bottom);
    SelectObject(hdc, old_pen);
    DeleteObject(border_pen);

    // Setup text properties
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, RGB(0, 0, 0));
    HFONT font = CreateFont(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                            DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
    HFONT old_font = (HFONT)SelectObject(hdc, font);

    // Draw statistics
    RECT stats_rect = *rect;
    stats_rect.left += 10;
    stats_rect.top += 5;
    stats_rect.bottom = stats_rect.top + 20;

    char stats_text[256];
    sprintf(stats_text, "Activity Statistics:");
    DrawText(hdc, stats_text, -1, &stats_rect, DT_TOP | DT_LEFT);

    // Draw activity gauges
    int gauge_y = stats_rect.bottom + 5;
    int gauge_height = 16;
    int gauge_padding = 5;
    int label_width = 70;
    int gauge_width = rect->right - rect->left - label_width - 20;

    // File operations gauge
    RECT file_label_rect = { rect->left + 10, gauge_y, rect->left + label_width, gauge_y + gauge_height };
    DrawText(hdc, "Files:", -1, &file_label_rect, DT_VCENTER | DT_LEFT | DT_SINGLELINE);

    RECT file_gauge_rect = {
            rect->left + label_width + 5,
            gauge_y,
            rect->left + label_width + 5 + gauge_width,
            gauge_y + gauge_height
    };
    DrawResourceGauge(hdc, &file_gauge_rect, status->file_ops, 500, RGB(0, 255, 0), RGB(255, 0, 0));

    // Network operations gauge
    gauge_y += gauge_height + gauge_padding;
    RECT net_label_rect = { rect->left + 10, gauge_y, rect->left + label_width, gauge_y + gauge_height };
    DrawText(hdc, "Network:", -1, &net_label_rect, DT_VCENTER | DT_LEFT | DT_SINGLELINE);

    RECT net_gauge_rect = {
            rect->left + label_width + 5,
            gauge_y,
            rect->left + label_width + 5 + gauge_width,
            gauge_y + gauge_height
    };
    DrawResourceGauge(hdc, &net_gauge_rect, status->network_ops, 100, RGB(0, 255, 0), RGB(255, 0, 0));

    // Memory operations gauge
    gauge_y += gauge_height + gauge_padding;
    RECT mem_label_rect = { rect->left + 10, gauge_y, rect->left + label_width, gauge_y + gauge_height };
    DrawText(hdc, "Memory:", -1, &mem_label_rect, DT_VCENTER | DT_LEFT | DT_SINGLELINE);

    RECT mem_gauge_rect = {
            rect->left + label_width + 5,
            gauge_y,
            rect->left + label_width + 5 + gauge_width,
            gauge_y + gauge_height
    };
    DrawResourceGauge(hdc, &mem_gauge_rect, status->memory_ops, 200, RGB(0, 255, 0), RGB(255, 0, 0));

    // Cleanup
    SelectObject(hdc, old_font);
    DeleteObject(font);
}

// Draw a resource usage gauge
void DrawResourceGauge(HDC hdc, RECT* rect, int value, int max_value,
                       COLORREF low_color, COLORREF high_color) {
    if (!hdc || !rect) return;

    // Calculate percentage
    float percent = (float)value / max_value;
    if (percent > 1.0f) percent = 1.0f;

    // Draw background
    HBRUSH bg_brush = CreateSolidBrush(RGB(230, 230, 230));
    FillRect(hdc, rect, bg_brush);
    DeleteObject(bg_brush);

    // Draw border
    HPEN border_pen = CreatePen(PS_SOLID, 1, RGB(200, 200, 200));
    HPEN old_pen = (HPEN)SelectObject(hdc, border_pen);
    Rectangle(hdc, rect->left, rect->top, rect->right, rect->bottom);
    SelectObject(hdc, old_pen);
    DeleteObject(border_pen);

    // Calculate gradient color
    COLORREF gauge_color;

    if (percent < 0.5f) {
        // Interpolate between low and mid color
        int r = (low_color & 0xFF);
        int g = ((low_color >> 8) & 0xFF);
        int b = ((low_color >> 16) & 0xFF);

        int r2 = (RGB(255, 255, 0) & 0xFF);
        int g2 = ((RGB(255, 255, 0) >> 8) & 0xFF);
        int b2 = ((RGB(255, 255, 0) >> 16) & 0xFF);

        float t = percent * 2.0f;
        r = r + (int)((r2 - r) * t);
        g = g + (int)((g2 - g) * t);
        b = b + (int)((b2 - b) * t);

        gauge_color = RGB(r, g, b);
    } else {
        // Interpolate between mid and high color
        int r = (RGB(255, 255, 0) & 0xFF);
        int g = ((RGB(255, 255, 0) >> 8) & 0xFF);
        int b = ((RGB(255, 255, 0) >> 16) & 0xFF);

        int r2 = (high_color & 0xFF);
        int g2 = ((high_color >> 8) & 0xFF);
        int b2 = ((high_color >> 16) & 0xFF);

        float t = (percent - 0.5f) * 2.0f;
        r = r + (int)((r2 - r) * t);
        g = g + (int)((g2 - g) * t);
        b = b + (int)((b2 - b) * t);

        gauge_color = RGB(r, g, b);
    }

    // Draw gauge
    int gauge_width = (int)((rect->right - rect->left - 2) * percent);
    RECT gauge_rect = {
            rect->left + 1,
            rect->top + 1,
            rect->left + 1 + gauge_width,
            rect->bottom - 1
    };

    HBRUSH gauge_brush = CreateSolidBrush(gauge_color);
    FillRect(hdc, &gauge_rect, gauge_brush);
    DeleteObject(gauge_brush);

    // Draw text
    char text[32];
    sprintf(text, "%d / %d", value, max_value);

    SetTextColor(hdc, RGB(0, 0, 0));
    DrawText(hdc, text, -1, rect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

// Clean up container resources
void CleanupContainer(ContainerContext* context) {
    if (!context) return;

    // Kill timer
    if (context->container_window) {
        KillTimer(context->container_window, CONTAINER_REFRESH_ID);
    }

    // Terminate child process if still running
    if (context->child_process) {
        TerminateProcess(context->child_process, 0);
        CloseHandle(context->child_process);
        context->child_process = NULL;
    }

    // Delete brushes
    if (context->border_brush) {
        DeleteObject(context->border_brush);
        context->border_brush = NULL;
    }

    // Free the context
    if (context == g_context) {
        g_context = NULL;
    }

    free(context);
}

// Window procedure for container window
static LRESULT CALLBACK ContainerWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    // Get context from window
    ContainerContext* context = (ContainerContext*)GetWindowLongPtr(hwnd, GWLP_USERDATA);

    switch (msg) {
        case WM_CREATE:
            // Context isn't set yet during WM_CREATE
            return 0;

        case WM_SIZE:
            if (context && context->child_window) {
                ResizeChildWindow(context);

                // Update status bar rect
                RECT client_rect;
                GetClientRect(hwnd, &client_rect);
                context->status_rect.left = 0;
                context->status_rect.top = 0;
                context->status_rect.right = client_rect.right;
                context->status_rect.bottom = CONTAINER_STATUS_HEIGHT;
            }
            return 0;

        case WM_TIMER:
            if (wParam == CONTAINER_REFRESH_ID && context) {
                UpdateContainerStatus(context);
                return 0;
            }
            break;

        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);

            if (context) {
                // Get client area
                RECT client_rect;
                GetClientRect(hwnd, &client_rect);

                // Draw border
                DrawContainerBorder(hdc, &client_rect, context->border_brush);

                // Draw status bar at top
                RECT status_rect = {
                        0, 0,
                        client_rect.right, CONTAINER_STATUS_HEIGHT
                };
                DrawStatusBar(hdc, &status_rect, &context->status);

                // Draw info panel at bottom
                RECT info_rect = {
                        CONTAINER_BORDER_WIDTH,
                        client_rect.bottom - CONTAINER_INFO_HEIGHT,
                        client_rect.right - CONTAINER_BORDER_WIDTH,
                        client_rect.bottom - CONTAINER_BORDER_WIDTH
                };
                DrawInfoPanel(hdc, &info_rect, &context->status);
            }

            EndPaint(hwnd, &ps);
            return 0;
        }

        case WM_CLOSE:
            if (context && context->child_process) {
                // Confirm before closing
                if (MessageBox(hwnd, "Close the monitored application?",
                               "ShadowVM", MB_YESNO | MB_ICONQUESTION) == IDYES) {
                    // Terminate child process
                    TerminateProcess(context->child_process, 0);
                    CloseHandle(context->child_process);
                    context->child_process = NULL;
                    DestroyWindow(hwnd);
                }
                return 0;
            }
            break;

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;

        case WM_USER + 100:  // Custom message for process termination
            if (context) {
                char msg[128];
                sprintf(msg, "Monitored process has terminated (Exit code: %lu)", (DWORD)wParam);
                MessageBox(hwnd, msg, "ShadowVM", MB_OK | MB_ICONINFORMATION);
                PostQuitMessage(0);
            }
            return 0;
    }

    return DefWindowProc(hwnd, msg, wParam, lParam);
}

// Callback for finding windows belonging to a process
static BOOL CALLBACK FindProcessWindowCallback(HWND hwnd, LPARAM lParam) {
    struct {
        DWORD process_id;
        HWND found_window;
    }* params = (void*)lParam;

    if (!IsWindowVisible(hwnd))
        return TRUE;  // Skip invisible windows

    DWORD window_pid = 0;
    GetWindowThreadProcessId(hwnd, &window_pid);

    if (window_pid == params->process_id) {
        // Check if window has a title
        char title[256] = {0};
        GetWindowText(hwnd, title, sizeof(title));

        if (title[0] != '\0') {
            char class_name[256] = {0};
            GetClassName(hwnd, class_name, sizeof(class_name));

            // Skip certain system windows
            if (!strstr(class_name, "IME") &&
                !strstr(class_name, "MSCTF")) {
                params->found_window = hwnd;
                return FALSE;  // Stop enumeration
            }
        }
    }

    return TRUE;  // Continue enumeration
}

// Find the main window of a process
static HWND FindProcessMainWindow(DWORD process_id) {
    struct {
        DWORD process_id;
        HWND found_window;
    } params = {
            .process_id = process_id,
            .found_window = NULL
    };

    EnumWindows(FindProcessWindowCallback, (LPARAM)&params);
    return params.found_window;
}

// Get memory usage of a process
static SIZE_T GetProcessMemoryUsage(HANDLE process) {
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(process, &pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize;
    }
    return 0;
}

// Implementation of the missing function - add this to container.c
BOOL DetectSecurityViolation(const ActivityRecord* activity) {
    if (!activity) return false;

    // Check based on resource type
    switch (activity->resource_type) {
        case RESOURCE_FILE_SYSTEM:
            // Check for access to sensitive system files
            if (strstr(activity->file.path, "\\Windows\\System32\\") &&
                activity->file.access_type & ACCESS_WRITE) {
                return true;
            }
            break;

        case RESOURCE_NETWORK:
            // Check for connections to suspicious ports
            if (activity->network.remote_port == 4444 ||  // Common backdoor port
                activity->network.remote_port == 31337) {  // Elite backdoor port
                return true;
            }
            break;

        case RESOURCE_MEMORY:
            // Check for large executable memory allocations
            if ((activity->memory.protection & PAGE_EXECUTE_READWRITE) &&
                activity->memory.size > 1024*1024) {  // More than 1MB
                return true;
            }
            break;

        case RESOURCE_REGISTRY:
            // Check for access to sensitive registry keys
            if ((strstr(activity->registry.key_path, "\\SYSTEM\\CurrentControlSet\\Services") ||
                 strstr(activity->registry.key_path, "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")) &&
                activity->registry.access_type & ACCESS_REGISTRY_SET) {
                return true;
            }
            break;
    }

    return false;
}