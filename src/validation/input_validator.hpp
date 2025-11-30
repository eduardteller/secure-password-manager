#ifndef INPUT_VALIDATOR_HPP
#define INPUT_VALIDATOR_HPP

#include <string>
#include <stdexcept>

class ValidationError : public std::runtime_error {
public:
    explicit ValidationError(const std::string& message) 
        : std::runtime_error(message) {}
};

class InputValidator {
public:
    // Validate service name (alphanumeric, dashes, dots, underscores)
    static bool validateServiceName(const std::string& service);
    
    // Validate username (email or alphanumeric)
    static bool validateUsername(const std::string& username);
    
    // Validate password for storage
    static bool validatePassword(const std::string& password);
    
    // Validate master password (minimum requirements)
    static bool validateMasterPassword(const std::string& password);
    
    // Validate file path (prevent directory traversal)
    static bool validateFilePath(const std::string& path);
    
    // Sanitize string input (remove potentially dangerous characters)
    static std::string sanitize(const std::string& input);
    
    // Throw ValidationError if validation fails
    static void requireValidServiceName(const std::string& service);
    static void requireValidUsername(const std::string& username);
    static void requireValidPassword(const std::string& password);
    static void requireValidMasterPassword(const std::string& password);
    static void requireValidFilePath(const std::string& path);

private:
    static constexpr size_t MAX_SERVICE_NAME_LENGTH = 256;
    static constexpr size_t MAX_USERNAME_LENGTH = 256;
    static constexpr size_t MIN_PASSWORD_LENGTH = 1;
    static constexpr size_t MAX_PASSWORD_LENGTH = 1024;
    static constexpr size_t MIN_MASTER_PASSWORD_LENGTH = 8;
    static constexpr size_t MAX_MASTER_PASSWORD_LENGTH = 256;
    
    static bool isAlphanumericWithSpecial(const std::string& str, const std::string& allowed);
    static bool isValidEmail(const std::string& email);
    static bool containsDirectoryTraversal(const std::string& path);
};

#endif // INPUT_VALIDATOR_HPP

