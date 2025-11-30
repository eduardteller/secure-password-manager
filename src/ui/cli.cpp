#include "cli.hpp"
#include "../storage/vault.hpp"
#include "../logging/logger.hpp"
#include "../validation/input_validator.hpp"
#include <iostream>
#include <termios.h>
#include <unistd.h>
#include <cstdlib>
#include <sys/stat.h>

CLI::CLI() : vault_(std::make_unique<Vault>()) {
    vaultPath_ = getDefaultVaultPath();
}

CLI::~CLI() {
    // Cleanup
}

std::string CLI::getDefaultVaultPath() {
    const char* home = getenv("HOME");
    if (!home) {
        return "./vault.spm";
    }
    std::string path = std::string(home) + "/.spm_vault";
    return path;
}

std::string CLI::getPassword(const std::string& prompt) {
    std::cout << prompt;
    std::cout.flush();
    
    // Disable echo
    termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    
    std::string password;
    std::getline(std::cin, password);
    
    // Re-enable echo
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << std::endl;
    
    return InputValidator::sanitize(password);
}

std::string CLI::getInput(const std::string& prompt) {
    std::cout << prompt;
    std::cout.flush();
    
    std::string input;
    std::getline(std::cin, input);
    
    return InputValidator::sanitize(input);
}

bool CLI::confirmAction(const std::string& prompt) {
    std::string response = getInput(prompt + " (yes/no): ");
    return (response == "yes" || response == "y");
}

int CLI::run(int argc, char* argv[]) {
    std::cout << "DEBUG: Entering CLI::run" << std::endl;
    // Initialize logger
    const char* home = getenv("HOME");
    std::string logPath = home ? (std::string(home) + "/.spm_log") : "./spm_log";
    
    std::cout << "DEBUG: Initializing logger at " << logPath << std::endl;
    Logger::getInstance().initialize(logPath);
    std::cout << "DEBUG: Logger initialized" << std::endl;
    
    if (argc < 2) {
        printHelp();
        return 0;
    }

    std::string command = argv[1];

    try {
        if (command == "help" || command == "--help" || command == "-h") {
            printHelp();
        } else if (command == "version" || command == "--version" || command == "-v") {
            printVersion();
        } else if (command == "init") {
            handleInit();
        } else if (command == "add") {
            handleAdd();
        } else if (command == "get") {
            handleGet();
        } else if (command == "list") {
            handleList();
        } else if (command == "delete") {
            handleDelete();
        } else if (command == "update") {
            handleUpdate();
        } else {
            std::cerr << "Error: Unknown command: " << command << std::endl;
            printHelp();
            return 1;
        }
    } catch (const ValidationError& e) {
        std::cerr << "Validation error: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Error: Operation failed" << std::endl;
        return 1;
    }

    return 0;
}

void CLI::printHelp() {
    std::cout << "Secure Password Manager - Help" << std::endl;
    std::cout << "\nUsage: spm <command> [options]" << std::endl;
    std::cout << "\nCommands:" << std::endl;
    std::cout << "  init         Initialize a new password vault" << std::endl;
    std::cout << "  add          Add a new password entry" << std::endl;
    std::cout << "  get          Retrieve a password" << std::endl;
    std::cout << "  update       Update an existing password" << std::endl;
    std::cout << "  list         List all services" << std::endl;
    std::cout << "  delete       Delete a password entry" << std::endl;
    std::cout << "  help         Show this help message" << std::endl;
    std::cout << "  version      Show version information" << std::endl;
    std::cout << "\nSecurity Features:" << std::endl;
    std::cout << "  - AES-256-GCM encryption for stored passwords" << std::endl;
    std::cout << "  - PBKDF2 key derivation for master password" << std::endl;
    std::cout << "  - Secure memory wiping for sensitive data" << std::endl;
    std::cout << "  - Input validation and sanitization" << std::endl;
    std::cout << "  - Comprehensive audit logging" << std::endl;
    std::cout << "\nDefault vault location: " << vaultPath_ << std::endl;
}

void CLI::printVersion() {
    std::cout << "Secure Password Manager v1.0.0" << std::endl;
    std::cout << "Built with OpenSSL for cryptographic operations" << std::endl;
}

void CLI::handleInit() {
    std::cout << "=== Initialize Password Vault ===" << std::endl;
    std::cout << "Vault will be created at: " << vaultPath_ << std::endl;
    
    if (Vault::vaultExists(vaultPath_)) {
        std::cerr << "Error: Vault already exists at this location" << std::endl;
        std::cerr << "Use 'spm add' to add entries to existing vault" << std::endl;
        return;
    }
    
    std::cout << "\nMaster password requirements:" << std::endl;
    std::cout << "  - At least 8 characters" << std::endl;
    std::cout << "  - Contains uppercase letter" << std::endl;
    std::cout << "  - Contains lowercase letter" << std::endl;
    std::cout << "  - Contains digit" << std::endl;
    
    std::string masterPassword = getPassword("\nEnter master password: ");
    std::string confirmPassword = getPassword("Confirm master password: ");
    
    if (masterPassword != confirmPassword) {
        std::cerr << "Error: Passwords do not match" << std::endl;
        return;
    }
    
    try {
        if (vault_->initialize(vaultPath_, masterPassword)) {
            std::cout << "Success: Vault initialized successfully" << std::endl;
            std::cout << "You can now add passwords using 'spm add'" << std::endl;
        } else {
            std::cerr << "Error: Failed to initialize vault" << std::endl;
        }
    } catch (const ValidationError& e) {
        std::cerr << "Validation error: " << e.what() << std::endl;
    }
}

void CLI::handleAdd() {
    std::cout << "=== Add Password Entry ===" << std::endl;
    
    if (!Vault::vaultExists(vaultPath_)) {
        std::cerr << "Error: Vault does not exist. Use 'spm init' first" << std::endl;
        return;
    }
    
    std::string masterPassword = getPassword("Enter master password: ");
    
    if (!vault_->load(vaultPath_, masterPassword)) {
        std::cerr << "Error: Authentication failed" << std::endl;
        return;
    }
    
    std::string service = getInput("Enter service name (e.g., github.com): ");
    std::string username = getInput("Enter username/email: ");
    std::string password = getPassword("Enter password: ");
    
    try {
        vault_->setPassword(service, username, password);
        std::cout << "Success: Password added for " << service << std::endl;
    } catch (const ValidationError& e) {
        std::cerr << "Validation error: " << e.what() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: Failed to add password" << std::endl;
    }
    
    vault_->lock();
}

void CLI::handleGet() {
    std::cout << "=== Retrieve Password ===" << std::endl;
    
    if (!Vault::vaultExists(vaultPath_)) {
        std::cerr << "Error: Vault does not exist. Use 'spm init' first" << std::endl;
        return;
    }
    
    std::string masterPassword = getPassword("Enter master password: ");
    
    if (!vault_->load(vaultPath_, masterPassword)) {
        std::cerr << "Error: Authentication failed" << std::endl;
        return;
    }
    
    std::string service = getInput("Enter service name: ");
    std::string username = getInput("Enter username/email: ");
    
    try {
        std::string password = vault_->getPassword(service, username);
        std::cout << "\nService: " << service << std::endl;
        std::cout << "Username: " << username << std::endl;
        std::cout << "Password: " << password << std::endl;
        std::cout << "\n*** Remember to clear your screen after copying! ***" << std::endl;
    } catch (const ValidationError& e) {
        std::cerr << "Validation error: " << e.what() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: Password not found or retrieval failed" << std::endl;
    }
    
    vault_->lock();
}

void CLI::handleUpdate() {
    std::cout << "=== Update Password ===" << std::endl;
    
    if (!Vault::vaultExists(vaultPath_)) {
        std::cerr << "Error: Vault does not exist. Use 'spm init' first" << std::endl;
        return;
    }
    
    std::string masterPassword = getPassword("Enter master password: ");
    
    if (!vault_->load(vaultPath_, masterPassword)) {
        std::cerr << "Error: Authentication failed" << std::endl;
        return;
    }
    
    std::string service = getInput("Enter service name: ");
    std::string username = getInput("Enter username/email: ");
    
    // Verify entry exists
    try {
        vault_->getPassword(service, username);
    } catch (...) {
        std::cerr << "Error: Entry not found" << std::endl;
        vault_->lock();
        return;
    }
    
    std::string newPassword = getPassword("Enter new password: ");
    
    try {
        vault_->setPassword(service, username, newPassword);
        std::cout << "Success: Password updated for " << service << std::endl;
    } catch (const ValidationError& e) {
        std::cerr << "Validation error: " << e.what() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: Failed to update password" << std::endl;
    }
    
    vault_->lock();
}

void CLI::handleList() {
    std::cout << "=== List Services ===" << std::endl;
    
    if (!Vault::vaultExists(vaultPath_)) {
        std::cerr << "Error: Vault does not exist. Use 'spm init' first" << std::endl;
        return;
    }
    
    std::string masterPassword = getPassword("Enter master password: ");
    
    if (!vault_->load(vaultPath_, masterPassword)) {
        std::cerr << "Error: Authentication failed" << std::endl;
        return;
    }
    
    try {
        std::vector<std::string> services = vault_->listServices();
        
        if (services.empty()) {
            std::cout << "No entries in vault" << std::endl;
        } else {
            std::cout << "\nStored services (" << services.size() << "):" << std::endl;
            for (const auto& service : services) {
                std::cout << "  - " << service << std::endl;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: Failed to list services" << std::endl;
    }
    
    vault_->lock();
}

void CLI::handleDelete() {
    std::cout << "=== Delete Password Entry ===" << std::endl;
    
    if (!Vault::vaultExists(vaultPath_)) {
        std::cerr << "Error: Vault does not exist" << std::endl;
        return;
    }
    
    std::string masterPassword = getPassword("Enter master password: ");
    
    if (!vault_->load(vaultPath_, masterPassword)) {
        std::cerr << "Error: Authentication failed" << std::endl;
        return;
    }
    
    std::string service = getInput("Enter service name: ");
    std::string username = getInput("Enter username/email: ");
    
    if (!confirmAction("Are you sure you want to delete this entry?")) {
        std::cout << "Deletion cancelled" << std::endl;
        vault_->lock();
        return;
    }
    
    try {
        if (vault_->deletePassword(service, username)) {
            std::cout << "Success: Entry deleted" << std::endl;
        } else {
            std::cerr << "Error: Entry not found" << std::endl;
        }
    } catch (const ValidationError& e) {
        std::cerr << "Validation error: " << e.what() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: Failed to delete entry" << std::endl;
    }
    
    vault_->lock();
}

