cmake_minimum_required(VERSION 3.16)
project(SecurePasswordManager LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(APPLE)
    execute_process(COMMAND uname -m OUTPUT_VARIABLE ARCH OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(CMAKE_OSX_ARCHITECTURES "${ARCH}")
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

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang|AppleClang|GNU")
    target_compile_options(spm PRIVATE -Wall -Wextra -Wpedantic)
endif()

