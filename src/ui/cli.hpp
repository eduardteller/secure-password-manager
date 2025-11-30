#ifndef CLI_HPP
#define CLI_HPP

#include <string>
#include <memory>

class Vault;

class CLI {
public:
    CLI();
    ~CLI();

    int run(int argc, char* argv[]);

private:
    void printHelp();
    void printVersion();
    
    void handleInit();
    void handleAdd();
    void handleGet();
    void handleList();
    void handleDelete();
    void handleUpdate();
    
    std::string getPassword(const std::string& prompt);
    std::string getInput(const std::string& prompt);
    bool confirmAction(const std::string& prompt);
    std::string getDefaultVaultPath();
    bool copyToClipboard(const std::string& text);
    void clearClipboardAfterDelay(int seconds);
    
    std::unique_ptr<Vault> vault_;
    std::string vaultPath_;
};

#endif

