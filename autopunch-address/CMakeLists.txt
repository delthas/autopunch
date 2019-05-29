cmake_minimum_required(VERSION 3.12)
project(autopunch C CXX)

set(CMAKE_C_STANDARD 11)

# compile with i386 mingw
add_executable(address address.c)
target_compile_definitions(address PRIVATE -DWIN32_LEAN_AND_MEAN)
target_link_options(address PRIVATE -mwindows $<$<CONFIG:RELEASE>:-s> $<$<CONFIG:MINSIZEREL>:-s>)

add_custom_target(address_copy DEPENDS address COMMAND_EXPAND_LISTS VERBATIM
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:address> "${CMAKE_SOURCE_DIR}/address.exe")
