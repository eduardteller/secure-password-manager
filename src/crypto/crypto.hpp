#ifndef CRYPTO_HPP
#define CRYPTO_HPP

#include <string>
#include <vector>

class Crypto {
public:
    Crypto();
    ~Crypto();

    // Encrypt data with a given key
    std::vector<uint8_t> encrypt(const std::string& plaintext, const std::string& key);
    
    // Decrypt data with a given key
    std::string decrypt(const std::vector<uint8_t>& ciphertext, const std::string& key);
    
    // Generate a secure hash
    std::string hash(const std::string& input);
    
    // Verify a hash
    bool verifyHash(const std::string& input, const std::string& hash);

private:
    // Private implementation details
};

#endif // CRYPTO_HPP

