#ifndef CRYPTO_HPP
#define CRYPTO_HPP

#include <string>
#include <vector>
#include <array>

class Crypto {
public:
    Crypto();
    ~Crypto();

    // Encrypt data with a given key using AES-256-GCM
    // Returns: IV (12 bytes) + ciphertext + authentication tag (16 bytes)
    std::vector<uint8_t> encrypt(const std::string& plaintext, const std::string& key);
    
    // Decrypt data with a given key using AES-256-GCM
    // Expects: IV (12 bytes) + ciphertext + authentication tag (16 bytes)
    std::string decrypt(const std::vector<uint8_t>& ciphertext, const std::string& key);
    
    // Generate a secure hash using PBKDF2
    // Returns: base64(salt + hash)
    std::string hash(const std::string& input);
    
    // Verify a hash using constant-time comparison
    bool verifyHash(const std::string& input, const std::string& hashStr);
    
    // Securely wipe sensitive data from memory
    static void secureWipe(std::string& data);
    static void secureWipe(std::vector<uint8_t>& data);
    
    // Derive a key from password using PBKDF2
    std::vector<uint8_t> deriveKey(const std::string& password, const std::vector<uint8_t>& salt, size_t keyLen = 32);
    
    // Generate random bytes
    std::vector<uint8_t> randomBytes(size_t length);
    
    // Helper to convert binary to/from base64
    std::string toBase64(const std::vector<uint8_t>& data);
    std::vector<uint8_t> fromBase64(const std::string& data);

private:
    static constexpr size_t SALT_SIZE = 16;
    static constexpr size_t PBKDF2_ITERATIONS = 100000;
    static constexpr size_t IV_SIZE = 12;
    static constexpr size_t TAG_SIZE = 16;
    static constexpr size_t KEY_SIZE = 32; // AES-256
};

#endif // CRYPTO_HPP

