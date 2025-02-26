cmake_minimum_required(VERSION 3.30)
project(ShadowVM C)

set(CMAKE_C_STANDARD 99)

# Add compiler definitions
add_definitions(-DWIN32_LEAN_AND_MEAN)

# Source files in dependency order
set(SOURCE_FILES
        hook_system.c
        shadow_vm.c
        jail_layer.c
        security_system.c
        resource_hooks.c
        resource_monitor.c
        main.c
)

# Header files in dependency order
set(HEADER_FILES
        include/security_types.h
        include/resource_types.h
        include/hook_system.h
        include/resource_hooks.h
        include/resource_monitor.h
        include/jail_layer.h
        include/security_system.h
        include/shadow_vm.h
)

# Add include directory
include_directories(${PROJECT_SOURCE_DIR}/include)

# Create executable
add_executable(shadowvm ${SOURCE_FILES} ${HEADER_FILES})

# Link Windows libraries in correct order
target_link_libraries(shadowvm
        ws2_32      # Windows Sockets
        iphlpapi    # IP Helper API
        psapi       # Process Status API
        advapi32    # Advanced Windows 32 Base API
)

# Set Windows subsystem
set_target_properties(shadowvm PROPERTIES
        WIN32_EXECUTABLE FALSE  # Console application
)

# Enable warnings but don't treat them as errors initially while fixing
if(MSVC)
    target_compile_options(shadowvm PRIVATE /W4)
else()
    target_compile_options(shadowvm PRIVATE -Wall -Wextra)
endif()

if(MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /EHa")  # Enable async exception handling
endif()

# Set output directories
set_target_properties(shadowvm PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
        ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)

# Install rules
install(TARGETS shadowvm
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
)

# Install headers
install(FILES ${HEADER_FILES}
        DESTINATION include
)