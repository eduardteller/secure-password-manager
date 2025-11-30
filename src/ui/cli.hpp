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
    
    std::unique_ptr<Vault> vault_;
};

#endif // CLI_HPP

