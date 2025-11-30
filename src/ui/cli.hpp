#ifndef CLI_HPP
#define CLI_HPP

#include <string>
#include <memory>

class Vault;

class CLI {
public:
    CLI();
    ~CLI();

    // Main entry point for CLI
    int run(int argc, char* argv[]);

private:
    void printHelp();
    void printVersion();
    
    // Command handlers
    void handleInit();
    void handleAdd();
    void handleGet();
    void handleList();
    void handleDelete();
    void handleUpdate();
    
    // Helper methods
    std::string getPassword(const std::string& prompt);
    std::string getInput(const std::string& prompt);
    bool confirmAction(const std::string& prompt);
    std::string getDefaultVaultPath();
    
    std::unique_ptr<Vault> vault_;
    std::string vaultPath_;
};

#endif // CLI_HPP

