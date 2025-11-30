#ifndef VAULT_HPP
#define VAULT_HPP

#include <string>
#include <map>
#include <memory>

class Vault {
public:
    Vault();
    ~Vault();

    // Load vault from file
    bool load(const std::string& filepath, const std::string& masterPassword);
    
    // Save vault to file
    bool save(const std::string& filepath, const std::string& masterPassword);
    
    // Add or update a password entry
    void setPassword(const std::string& service, const std::string& username, const std::string& password);
    
    // Retrieve a password entry
    std::string getPassword(const std::string& service, const std::string& username);
    
    // Delete a password entry
    bool deletePassword(const std::string& service, const std::string& username);
    
    // List all services
    std::vector<std::string> listServices();

private:
    struct Entry {
        std::string username;
        std::string password;
    };
    
    std::map<std::string, Entry> entries_;
    bool isLocked_;
};

#endif // VAULT_HPP

