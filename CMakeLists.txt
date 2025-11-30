cmake_minimum_required(VERSION 3.16)
project(SecurePasswordManager LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(APPLE)
    execute_process(COMMAND uname -m OUTPUT_VARIABLE ARCH OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(CMAKE_OSX_ARCHITECTURES "${ARCH}")
endif()

if(DEFINED TARGET_ARCH)
    if(TARGET_ARCH STREQUAL "x86")
        if(MSVC)
            set(CMAKE_GENERATOR_PLATFORM Win32)
        else()
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32")
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32")
        endif()
    elseif(TARGET_ARCH STREQUAL "x64")
        if(MSVC)
            set(CMAKE_GENERATOR_PLATFORM x64)
        else()
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m64")
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m64")
        endif()
    endif()
endif()

add_executable(spm
    src/main.cpp
    src/crypto/crypto.cpp
    src/storage/vault.cpp
    src/ui/cli.cpp
    src/logging/logger.cpp
    src/validation/input_validator.cpp
)

target_include_directories(spm PRIVATE
    ${PROJECT_SOURCE_DIR}/src
    ${PROJECT_SOURCE_DIR}/include
)

find_package(OpenSSL REQUIRED)
target_link_libraries(spm PRIVATE OpenSSL::SSL OpenSSL::Crypto)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|AppleClang|GNU")
    target_compile_options(spm PRIVATE -Wall -Wextra -Wpedantic)
elseif(MSVC)
    target_compile_options(spm PRIVATE /W4 /permissive-)
    target_compile_definitions(spm PRIVATE
        _CRT_SECURE_NO_WARNINGS
        NOMINMAX
        WIN32_LEAN_AND_MEAN
    )
endif()

if(WIN32)
    target_link_libraries(spm PRIVATE ws2_32 crypt32)
endif()
