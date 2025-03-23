cmake_minimum_required(VERSION 3.20)

set(CMAKE_C_STANDARD 23)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_program(CCACHE_PROGRAM ccache REQUIRED)
if(NOT CCACHE_PROGRAM)
    message(FATAL_ERROR "ccache not found! Please install ccache or adjust the configuration.")
endif()

if(NOT (UNIX AND NOT APPLE))
    message(FATAL_ERROR "ftrace is a Linux only tool.")
endif()

# Set ccache as the compiler launcher before setting the compiler
set(CMAKE_C_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")

set(optimization_flags
        -O3
        -march=native
        -mtune=native
        -flto
        -fomit-frame-pointer
        -ffast-math
        -fstrict-aliasing
        -fdata-sections
        -ffunction-sections
        -D_FORTIFY_SOURCE=2
        -fstack-protector-strong
        -Wl,-z,relro -Wl,-z,now
        -s
)

set(optimization_link_flags
        -O3
        -march=native
        -mtune=native
        -flto
        -fomit-frame-pointer
        -ffast-math
        -fstrict-aliasing
        -fdata-sections
        -ffunction-sections
        -Wl,--gc-sections
        -D_FORTIFY_SOURCE=2
        -fstack-protector-strong
        -Wl,-z,relro -Wl,-z,now
        -s
)

set(compiler_options
        # Warnings and diagnostics
        -Wall                                   # Enable common warnings
        -Wextra                                 # Enable extra warnings
        -Wpedantic                              # Strict compliance with the standard
        -Wunused                                # Warn about unused variables, functions, etc.
        -Wuninitialized                         # Warn if variables are used uninitialized
        -fdiagnostics-show-option               # Show which option triggered the warning
        -fdiagnostics-color=always              # Enable colored diagnostics for better readability

        # Debugging and stack protection
        -g3                                     # Maximum debug information, including macro expansions
        -O0
        -fstack-usage                           # Generate stack usage info for each function
        -fstack-protector-all                   # Protect all functions with a stack canary to prevent stack overflow attacks
        # -D_FORTIFY_SOURCE=2                   # Buffer overflow detection on safer libc functions (e.g., memcpy).
        # You need to enable optimization for _FORTIFY_SOURCE to work!
        -gdwarf-4                               # Generate DWARF version 4 debug information

        -fno-eliminate-unused-debug-types
        -fno-omit-frame-pointer
        -lasan -lubsan # -fPIC --pie
        -Wl,-z,relro -Wl,-z,now
        -fstack-protector-all
)

set(linker_options
        # Linker options for memory safety, thread safety, and verbose debugging
        -Wl,--no-omagic                         # Prevent the generation of object files in memory; useful for debugging
        -Wl,--as-needed                         # Only link libraries that are actually needed to reduce binary size
        -Wl,--fatal-warnings                    # Treat all linker warnings as errors to catch issues early
        -Wl,-z,relro                            # Read-only relocations to prevent certain memory exploits (optional)
        -Wl,-z,now                              # Fully resolve all symbols during the link time for extra safety
        -Wl,-z,noexecstack                      # Prevent execution of code on the stack (security hardening)
        -Wl,-z,defs                             # Ensure all symbols are defined, and prevent undefined symbols
        -Wl,-O0

        -gdwarf-4                               # Generate detailed debug information for the linker
        -fno-eliminate-unused-debug-types
        -fno-omit-frame-pointer

        # Stack protection
        -fstack-protector-all                   # Link with stack protection for all functions
        -lasan -lubsan # -fPIC --pie --whole-file
        -Wl,-z,relro -Wl,-z,now
)

project(ftrace-remake C CXX)

include_directories(src/include)

add_compile_definitions(__LOG_TO_STDOUT__)

if ("${COMPILE_WITH_MEMORY_SANITIZERS}" STREQUAL "True")
    message(STATUS "Sanitizers for memory enabled")
    list(APPEND compiler_options
            -fsanitize=address                  # Detect illegal memory access such as buffer overflows and use-after-free
            -fsanitize=undefined                # Detect undefined behavior like integer overflows and null dereferencing
            # Code coverage options
#            -fprofile-arcs                      # Enable code coverage instrumentation
#            -ftest-coverage                     # Generate coverage test data
    )

    list(APPEND linker_options
            -fsanitize=address                  # Link the AddressSanitizer runtime for memory integrity
            -fsanitize=undefined                # Link the UndefinedBehaviorSanitizer for detecting undefined behavior
            # Code coverage options
#            -fprofile-arcs                      # Enable code coverage instrumentation
#            -ftest-coverage                     # Generate coverage test data
    )
endif ()

if ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    add_compile_options(${compiler_options})
    add_link_options(${linker_options})
    add_compile_definitions(__DEBUG__)
else ()
    add_compile_options(${optimization_flags})
    add_compile_options(${optimization_link_flags})
endif ()

find_package(PkgConfig REQUIRED)
pkg_check_modules(CAPSTONE REQUIRED capstone)

add_executable(ftrace
        src/ftrace.cpp src/log.cpp src/include/log.hpp
        src/argument_parser.cpp
        src/include/argument_parser.h
)

target_include_directories(ftrace PRIVATE ${CAPSTONE_INCLUDE_DIRS})
target_link_libraries(ftrace PRIVATE ${CAPSTONE_LIBRARIES})
