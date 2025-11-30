#include "crypto.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <stdexcept>
#include <cstring>
#include <memory>

Crypto::Crypto() {
    // OpenSSL is automatically initialized in OpenSSL 1.1.0+
}

Crypto::~Crypto() {
    // Cleanup handled by OpenSSL automatically
}

std::vector<uint8_t> Crypto::randomBytes(size_t length) {
    std::vector<uint8_t> buffer(length);
    if (RAND_bytes(buffer.data(), static_cast<int>(length)) != 1) {
        throw std::runtime_error("Failed to generate random bytes");
    }
    return buffer;
}

std::vector<uint8_t> Crypto::deriveKey(const std::string& password, const std::vector<uint8_t>& salt, size_t keyLen) {
    std::vector<uint8_t> key(keyLen);
    
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "PBKDF2", nullptr);
    if (!kdf) {
        throw std::runtime_error("Failed to fetch PBKDF2 KDF");
    }
    
    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    
    if (!kctx) {
        throw std::runtime_error("Failed to create KDF context");
    }
    
    // Set up PBKDF2 parameters
    OSSL_PARAM params[4];
    params[0] = OSSL_PARAM_construct_octet_string("pass", 
                                                   const_cast<char*>(password.c_str()), 
                                                   password.length());
    params[1] = OSSL_PARAM_construct_octet_string("salt", 
                                                   const_cast<unsigned char*>(salt.data()), 
                                                   salt.size());
    int iterations = static_cast<int>(PBKDF2_ITERATIONS);
    params[2] = OSSL_PARAM_construct_int("iter", &iterations);
    params[3] = OSSL_PARAM_construct_end();
    
    if (EVP_KDF_derive(kctx, key.data(), key.size(), params) <= 0) {
        EVP_KDF_CTX_free(kctx);
        throw std::runtime_error("Key derivation failed");
    }
    
    EVP_KDF_CTX_free(kctx);
    return key;
}

std::string Crypto::hash(const std::string& input) {
    // Generate random salt
    std::vector<uint8_t> salt = randomBytes(SALT_SIZE);
    
    // Derive hash using PBKDF2
    std::vector<uint8_t> hash = deriveKey(input, salt, 32);
    
    // Combine salt + hash
    std::vector<uint8_t> combined;
    combined.insert(combined.end(), salt.begin(), salt.end());
    combined.insert(combined.end(), hash.begin(), hash.end());
    
    // Return as base64
    return toBase64(combined);
}

bool Crypto::verifyHash(const std::string& input, const std::string& hashStr) {
    try {
        // Decode the stored hash
        std::vector<uint8_t> combined = fromBase64(hashStr);
        
        if (combined.size() < SALT_SIZE) {
            return false;
        }
        
        // Extract salt and stored hash
        std::vector<uint8_t> salt(combined.begin(), combined.begin() + SALT_SIZE);
        std::vector<uint8_t> storedHash(combined.begin() + SALT_SIZE, combined.end());
        
        // Derive hash from input using the same salt
        std::vector<uint8_t> computedHash = deriveKey(input, salt, storedHash.size());
        
        // Constant-time comparison
        if (computedHash.size() != storedHash.size()) {
            return false;
        }
        
        return CRYPTO_memcmp(computedHash.data(), storedHash.data(), computedHash.size()) == 0;
    } catch (...) {
        return false;
    }
}

std::vector<uint8_t> Crypto::encrypt(const std::string& plaintext, const std::string& key) {
    // Generate random IV
    std::vector<uint8_t> iv = randomBytes(IV_SIZE);
    
    // Derive encryption key from password
    std::vector<uint8_t> salt = randomBytes(SALT_SIZE);
    std::vector<uint8_t> derivedKey = deriveKey(key, salt, KEY_SIZE);
    
    // Create cipher context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        secureWipe(derivedKey);
        throw std::runtime_error("Failed to create cipher context");
    }
    
    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, derivedKey.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        secureWipe(derivedKey);
        throw std::runtime_error("Failed to initialize encryption");
    }
    
    // Allocate output buffer
    std::vector<uint8_t> ciphertext(plaintext.length() + EVP_CIPHER_block_size(EVP_aes_256_gcm()));
    int len = 0;
    int ciphertext_len = 0;
    
    // Encrypt plaintext
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, 
                          reinterpret_cast<const unsigned char*>(plaintext.c_str()), 
                          static_cast<int>(plaintext.length())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        secureWipe(derivedKey);
        throw std::runtime_error("Encryption failed");
    }
    ciphertext_len = len;
    
    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        secureWipe(derivedKey);
        throw std::runtime_error("Encryption finalization failed");
    }
    ciphertext_len += len;
    ciphertext.resize(static_cast<size_t>(ciphertext_len));
    
    // Get authentication tag
    std::vector<uint8_t> tag(TAG_SIZE);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        secureWipe(derivedKey);
        throw std::runtime_error("Failed to get authentication tag");
    }
    
    EVP_CIPHER_CTX_free(ctx);
    secureWipe(derivedKey);
    
    // Combine: salt + IV + ciphertext + tag
    std::vector<uint8_t> result;
    result.insert(result.end(), salt.begin(), salt.end());
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    result.insert(result.end(), tag.begin(), tag.end());
    
    return result;
}

std::string Crypto::decrypt(const std::vector<uint8_t>& ciphertext, const std::string& key) {
    // Minimum size check: salt + IV + tag
    if (ciphertext.size() < SALT_SIZE + IV_SIZE + TAG_SIZE) {
        throw std::runtime_error("Invalid ciphertext: too short");
    }
    
    // Extract components
    std::vector<uint8_t> salt(ciphertext.begin(), ciphertext.begin() + SALT_SIZE);
    std::vector<uint8_t> iv(ciphertext.begin() + SALT_SIZE, 
                            ciphertext.begin() + SALT_SIZE + IV_SIZE);
    std::vector<uint8_t> tag(ciphertext.end() - TAG_SIZE, ciphertext.end());
    std::vector<uint8_t> encrypted(ciphertext.begin() + SALT_SIZE + IV_SIZE, 
                                   ciphertext.end() - TAG_SIZE);
    
    // Derive decryption key
    std::vector<uint8_t> derivedKey = deriveKey(key, salt, KEY_SIZE);
    
    // Create cipher context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        secureWipe(derivedKey);
        throw std::runtime_error("Failed to create cipher context");
    }
    
    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, derivedKey.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        secureWipe(derivedKey);
        throw std::runtime_error("Failed to initialize decryption");
    }
    
    // Allocate output buffer
    std::vector<uint8_t> plaintext(encrypted.size() + EVP_CIPHER_block_size(EVP_aes_256_gcm()));
    int len = 0;
    int plaintext_len = 0;
    
    // Decrypt ciphertext
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, encrypted.data(), 
                          static_cast<int>(encrypted.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        secureWipe(derivedKey);
        throw std::runtime_error("Decryption failed");
    }
    plaintext_len = len;
    
    // Set authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        secureWipe(derivedKey);
        throw std::runtime_error("Failed to set authentication tag");
    }
    
    // Finalize decryption (this verifies the tag)
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        secureWipe(derivedKey);
        throw std::runtime_error("Decryption failed: authentication tag mismatch");
    }
    plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    secureWipe(derivedKey);
    
    plaintext.resize(static_cast<size_t>(plaintext_len));
    std::string result(plaintext.begin(), plaintext.end());
    secureWipe(plaintext);
    
    return result;
}

void Crypto::secureWipe(std::string& data) {
    if (!data.empty()) {
        OPENSSL_cleanse(&data[0], data.size());
        data.clear();
    }
}

void Crypto::secureWipe(std::vector<uint8_t>& data) {
    if (!data.empty()) {
        OPENSSL_cleanse(data.data(), data.size());
        data.clear();
    }
}

std::string Crypto::toBase64(const std::vector<uint8_t>& data) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    
    BIO_write(bio, data.data(), static_cast<int>(data.size()));
    BIO_flush(bio);
    
    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);
    
    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    
    return result;
}

std::vector<uint8_t> Crypto::fromBase64(const std::string& data) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new_mem_buf(data.c_str(), static_cast<int>(data.length()));
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    
    std::vector<uint8_t> result(data.length());
    int decodedLength = BIO_read(bio, result.data(), static_cast<int>(data.length()));
    BIO_free_all(bio);
    
    if (decodedLength < 0) {
        throw std::runtime_error("Base64 decoding failed");
    }
    
    result.resize(static_cast<size_t>(decodedLength));
    return result;
}

