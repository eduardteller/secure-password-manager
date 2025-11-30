#ifndef VAULT_HPP
#define VAULT_HPP

#include <string>
#include <map>
#include <memory>
#include <vector>
#include <utility>

class Crypto;

class Vault {
public:
    Vault();
    ~Vault();

    bool initialize(const std::string& filepath, const std::string& masterPassword);
    
    bool load(const std::string& filepath, const std::string& masterPassword);
    
    bool save();
    
    bool unlock(const std::string& masterPassword);
    
    void lock();
    
    bool isLocked() const { return isLocked_; }
    
    void setPassword(const std::string& service, const std::string& username, const std::string& password);
    
    std::string getPassword(const std::string& service, const std::string& username);
    
    std::pair<std::string, std::string> getCredentials(const std::string& service);
    
    bool deletePassword(const std::string& service, const std::string& username);
    
    bool deleteEntry(const std::string& service);
    
    std::vector<std::string> listServices();
    
    static bool vaultExists(const std::string& filepath);
    
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
    
    std::string serializeToJson();
    
    bool deserializeFromJson(const std::string& json);
    
    void requireUnlocked();
    
    static void setSecurePermissions(const std::string& filepath);
    
    std::map<std::string, Entry> entries_;
    std::unique_ptr<Crypto> crypto_;
    std::string filepath_;
    std::string masterPasswordHash_;
    std::string currentMasterPassword_;
    std::string sessionId_;
    bool isLocked_;
    bool initialized_;
};

#endif

