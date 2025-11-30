cmake_minimum_required(VERSION 3.15)

# Test executable
add_executable(test_runner
    test_main.cpp
)

# Link with source files (excluding main.cpp)
target_sources(test_runner PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/crypto/crypto.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/storage/vault.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/ui/cli.cpp
)

# Include directories
target_include_directories(test_runner PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
)

# Add test
add_test(NAME BasicTests COMMAND test_runner)

