cmake_minimum_required(VERSION 3.12)
project(autopunch_test C CXX)

set(CMAKE_C_STANDARD 11)

add_executable(autopunch_test
        inject.c
		test.c)
target_link_libraries(autopunch_test PRIVATE ws2_32)
target_compile_definitions(autopunch_test PRIVATE -DWIN32_LEAN_AND_MEAN -D_CRT_SECURE_NO_WARNINGS -DNDLL -D_DEBUG -D_CRTDBG_MAP_ALLOC)
target_compile_options(autopunch_test PRIVATE /Zi /Od /MTd /DEBUG)