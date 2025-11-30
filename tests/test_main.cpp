#include <iostream>
#include "../src/crypto/crypto.hpp"
#include "../src/storage/vault.hpp"

// Simple test runner
int main() {
    std::cout << "Running tests..." << std::endl;
    
    int passed = 0;
    int failed = 0;
    
    // Test 1: Crypto initialization
    try {
        Crypto crypto;
        std::cout << "[PASS] Crypto initialization" << std::endl;
        passed++;
    } catch (const std::exception& e) {
        std::cerr << "[FAIL] Crypto initialization: " << e.what() << std::endl;
        failed++;
    }
    
    // Test 2: Vault initialization
    try {
        Vault vault;
        std::cout << "[PASS] Vault initialization" << std::endl;
        passed++;
    } catch (const std::exception& e) {
        std::cerr << "[FAIL] Vault initialization: " << e.what() << std::endl;
        failed++;
    }
    
    // Summary
    std::cout << "\n=======================" << std::endl;
    std::cout << "Tests passed: " << passed << std::endl;
    std::cout << "Tests failed: " << failed << std::endl;
    std::cout << "=======================" << std::endl;
    
    return (failed == 0) ? 0 : 1;
}

