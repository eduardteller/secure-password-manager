#ifndef CRYPTO_HPP
#define CRYPTO_HPP

#include <string>
#include <vector>
#include <array>
#include <cstdint>

class Crypto {
public:
    Crypto();
    ~Crypto();

    std::vector<uint8_t> encrypt(const std::string& plaintext, const std::string& key);
    
    std::string decrypt(const std::vector<uint8_t>& ciphertext, const std::string& key);
    
    std::string hash(const std::string& input);
    
    bool verifyHash(const std::string& input, const std::string& hashStr);
    
    static void secureWipe(std::string& data);
    static void secureWipe(std::vector<uint8_t>& data);
    
    std::vector<uint8_t> deriveKey(const std::string& password, const std::vector<uint8_t>& salt, size_t keyLen = 32);
    
    std::vector<uint8_t> randomBytes(size_t length);
    
    std::string toBase64(const std::vector<uint8_t>& data);
    std::vector<uint8_t> fromBase64(const std::string& data);

private:
    static constexpr size_t SALT_SIZE = 16;
    static constexpr size_t PBKDF2_ITERATIONS = 100000;
    static constexpr size_t IV_SIZE = 12;
    static constexpr size_t TAG_SIZE = 16;
    static constexpr size_t KEY_SIZE = 32;
};

#endif

