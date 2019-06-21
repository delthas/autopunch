cmake_minimum_required(VERSION 3.12)
project(autopunch C CXX)

set(CMAKE_C_STANDARD 11)

# /W4 /WX /Zi /MT /Gy /Gm- /Zl /Od

# DETOURS_TARGET_PROCESSOR=X64
# DETOURS_OPTION_PROCESSOR=X86
# DETOURS_OPTION_BITS=32

add_library(autopunch MODULE
        detours/src/detours.cpp
        detours/src/modules.cpp
        detours/src/disasm.cpp
        detours/src/image.cpp
        detours/src/creatwth.cpp
        detours/src/disolx86.cpp
        detours/src/disolx64.cpp
        detours/src/disolia64.cpp
        detours/src/disolarm.cpp
        detours/src/disolarm64.cpp
        inject.c)
target_include_directories(autopunch PRIVATE detours/src)
target_link_libraries(autopunch PRIVATE ws2_32)
target_compile_definitions(autopunch PRIVATE -DWIN32_LEAN_AND_MEAN -D_CRT_SECURE_NO_WARNINGS)
target_compile_options(autopunch PRIVATE)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(TARGET_FILE_BITS 64)
else()
    set(TARGET_FILE_BITS 86)
endif()
if(CMAKE_BUILD_TYPE STREQUAL Debug)
    set(TARGET_FILE_BUILD dbg)
else()
    set(TARGET_FILE_BUILD rel)
endif()

add_custom_target(autopunch_copy DEPENDS autopunch COMMAND_EXPAND_LISTS VERBATIM
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:autopunch> ${CMAKE_SOURCE_DIR}/../autopunch-loader/autopunch.x${TARGET_FILE_BITS}.${TARGET_FILE_BUILD}.dll)
