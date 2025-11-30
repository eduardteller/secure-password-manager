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
    static bool validateServiceName(const std::string& service);
    
    static bool validateUsername(const std::string& username);
    
    static bool validatePassword(const std::string& password);
    
    static bool validateMasterPassword(const std::string& password);
    
    static bool validateFilePath(const std::string& path);
    
    static std::string sanitize(const std::string& input);
    
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

#endif

