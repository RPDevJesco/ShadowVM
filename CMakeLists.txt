cmake_minimum_required(VERSION 3.30)
project(ShadowVM C)

set(CMAKE_C_STANDARD 99)

add_executable(shadowvm main.c)
target_link_libraries(shadowvm psapi)