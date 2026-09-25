cmake_minimum_required(VERSION 3.13)
project(crashlens VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

option(CRASHLENS_BUILD_TESTS "Build the unit test suite" ON)
option(CRASHLENS_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(CRASHLENS_WERROR "Treat compiler warnings as errors" OFF)

if(MSVC)
    add_compile_options(/W4)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
    if(CRASHLENS_WERROR)
        add_compile_options(/WX)
    endif()
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
                        -Wmissing-prototypes -Wformat=2)
    if(CRASHLENS_WERROR)
        add_compile_options(-Werror)
    endif()
endif()

if(MINGW)
    # C99-conforming printf, so PRIx64 and friends need no MS extensions.
    add_compile_definitions(__USE_MINGW_ANSI_STDIO=1)
    # Older MinGW headers leave GCC checking formats against the MS runtime
    # and flag valid %lld/%llx; the other toolchains still check formats.
    add_compile_options(-Wno-format)
endif()

if(CRASHLENS_SANITIZE)
    if(MSVC)
        add_compile_options(/fsanitize=address)
    else()
        add_compile_options(-fsanitize=address,undefined -fno-sanitize-recover=all
                            -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address,undefined)
    endif()
endif()

add_library(crashlens_core STATIC
    src/cluster.c
    src/crash_event.c
    src/fingerprint.c
    src/fs.c
    src/parser.c
    src/parser_native.c
    src/parser_sanitizer.c
    src/report.c
    src/symbols.c
    src/util.c
)
target_include_directories(crashlens_core
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_executable(crashlens src/main.c)
target_link_libraries(crashlens PRIVATE crashlens_core)

if(CRASHLENS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
