#ifndef VAULT_HPP
#define VAULT_HPP

#include <string>
#include <map>
#include <memory>
#include <vector>

class Crypto;

class Vault {
public:
    Vault();
    ~Vault();

    // Initialize a new vault with master password
    bool initialize(const std::string& filepath, const std::string& masterPassword);
    
    // Load vault from file
    bool load(const std::string& filepath, const std::string& masterPassword);
    
    // Save vault to file
    bool save();
    
    // Unlock vault with master password
    bool unlock(const std::string& masterPassword);
    
    // Lock the vault
    void lock();
    
    // Check if vault is locked
    bool isLocked() const { return isLocked_; }
    
    // Add or update a password entry
    void setPassword(const std::string& service, const std::string& username, const std::string& password);
    
    // Retrieve a password entry
    std::string getPassword(const std::string& service, const std::string& username);
    
    // Delete a password entry
    bool deletePassword(const std::string& service, const std::string& username);
    
    // List all services
    std::vector<std::string> listServices();
    
    // Check if vault file exists and is valid
    static bool vaultExists(const std::string& filepath);
    
    // Generate session ID for logging
    std::string getSessionId() const { return sessionId_; }

private:
    struct Entry {
        std::vector<uint8_t> encryptedUsername;
        std::vector<uint8_t> encryptedPassword;
    };
    
    struct VaultData {
        std::string masterPasswordHash;
        std::string salt;
        std::map<std::string, Entry> entries;
    };
    
    // Serialize vault data to JSON
    std::string serializeToJson();
    
    // Deserialize vault data from JSON
    bool deserializeFromJson(const std::string& json);
    
    // Ensure vault is unlocked, throw if not
    void requireUnlocked();
    
    // Set file permissions to 0600
    static void setSecurePermissions(const std::string& filepath);
    
    std::map<std::string, Entry> entries_;
    std::unique_ptr<Crypto> crypto_;
    std::string filepath_;
    std::string masterPasswordHash_;
    std::string currentMasterPassword_;  // Stored only while unlocked, wiped on lock
    std::string sessionId_;
    bool isLocked_;
    bool initialized_;
};

#endif // VAULT_HPP

