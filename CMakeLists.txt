cmake_minimum_required(VERSION 3.16)
project(SecurePasswordManager LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# For macOS: prefer libc++ (usually default with clang)
set(CMAKE_OSX_ARCHITECTURES "arm64;x86_64" CACHE STRING "" FORCE)

# Add main executable
add_executable(spm
    src/main.cpp
    src/crypto/crypto.cpp
    src/storage/vault.cpp
    src/ui/cli.cpp
)

target_include_directories(spm PRIVATE
    ${PROJECT_SOURCE_DIR}/src
    ${PROJECT_SOURCE_DIR}/include
)

# Example: link OpenSSL if you choose to use it
find_package(OpenSSL REQUIRED)
target_link_libraries(spm PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# Enable extra warnings for secure coding
if (CMAKE_CXX_COMPILER_ID MATCHES "Clang|AppleClang|GNU")
    target_compile_options(spm PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
endif()

# Tests (we can wire this up later with a test framework)
enable_testing()
add_executable(spm_tests
    tests/test_main.cpp
)
add_test(NAME spm_tests COMMAND spm_tests)

