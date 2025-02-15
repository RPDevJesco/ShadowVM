# ShadowVM

ShadowVM is a lightweight user-space process VM that executes untrusted scripts and executables with process-level isolation. Unlike traditional VMs or containers, it runs at the process level, providing quick isolation without full OS overhead.

## Features

### Process-Level Isolation
- Uses process memory isolation instead of container/VM boundaries
- Leverages OS-provided process isolation mechanisms
- Creates a sandboxed environment within the process address space

### Resource Monitoring
- Tracks process memory usage (private and working set)
- Monitors file I/O operations
- Records process creation time and execution metrics
- Real-time activity monitoring with periodic updates

### File Access Control
- Path-based permissions using whitelist approach
- Extension-based filtering
- Special handling for Python runtime files
- Prevention of access to system directories

### Multi-Format Support
- Executes Python scripts (with interpreter detection)
- Runs Windows executables directly
- Handles command-line arguments

## Building

Requirements:
- CMake 3.30 or higher
- C99 compatible compiler
- Windows SDK

Build commands:
```bash
mkdir build
cd build
cmake ..
cmake --build .
```

## Usage

### Basic Usage
```bash
shadowvm.exe <executable_or_script> [args...]
```

### Examples
Running a Python script:
```bash
shadowvm.exe script.py arg1 arg2
```

Running an executable:
```bash
shadowvm.exe program.exe --param value
```

## Current Limitations

1. Security Scope
   - Basic process isolation only
   - Limited syscall interception
   - No privilege de-escalation
   - No network traffic controls

2. Execution Control
   - Cannot prevent all forms of inter-process communication
   - No DLL injection protection
   - Limited control over child processes

3. Resource Control
   - Basic memory and file I/O monitoring
   - No fine-grained resource limits
   - No network activity monitoring

## Use Cases

Current implementation is suitable for:
1. Development and testing environments
2. Process activity monitoring
3. Basic isolation of untrusted scripts
4. Resource usage analysis
5. Understanding process behavior

## Example Output

Running an application shows process isolation metrics:
```
=== Process Isolation Metrics ===
Private Memory Usage: 8278016 bytes
Working Set Size: 86982656 bytes
Process Start Time: 16:28:24.412

=== Process Activity Update ===
File I/O:
  Reads:  127 operations, 524288 bytes
  Writes: 45 operations, 131072 bytes
```

## Future Improvements

Planned enhancements:
1. Enhanced security features
   - Proper token restrictions
   - Job object constraints
   - Enhanced syscall filtering
2. Resource controls
   - Network activity monitoring
   - Memory limits enforcement
   - CPU usage restrictions
3. Better isolation
   - Registry virtualization
   - File system virtualization
   - GUI isolation

## License

[Insert your chosen license here]
