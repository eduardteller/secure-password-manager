#include "input_validator.hpp"
#include <algorithm>
#include <cctype>
#include <regex>

bool InputValidator::isAlphanumericWithSpecial(const std::string& str, const std::string& allowed) {
    return std::all_of(str.begin(), str.end(), [&allowed](char c) {
        return std::isalnum(static_cast<unsigned char>(c)) || 
               allowed.find(c) != std::string::npos;
    });
}

bool InputValidator::isValidEmail(const std::string& email) {
    const std::regex emailPattern(R"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})");
    return std::regex_match(email, emailPattern);
}

bool InputValidator::containsDirectoryTraversal(const std::string& path) {
    return path.find("..") != std::string::npos ||
           path.find("//") != std::string::npos ||
           path.find("\\\\") != std::string::npos;
}

bool InputValidator::validateServiceName(const std::string& service) {
    if (service.empty() || service.length() > MAX_SERVICE_NAME_LENGTH) {
        return false;
    }
    
    return isAlphanumericWithSpecial(service, "-._");
}

bool InputValidator::validateUsername(const std::string& username) {
    if (username.empty() || username.length() > MAX_USERNAME_LENGTH) {
        return false;
    }
    
    return isValidEmail(username) || 
           isAlphanumericWithSpecial(username, "-._@");
}

bool InputValidator::validatePassword(const std::string& password) {
    if (password.length() < MIN_PASSWORD_LENGTH || 
        password.length() > MAX_PASSWORD_LENGTH) {
        return false;
    }
    
    return password.find('\0') == std::string::npos;
}

bool InputValidator::validateMasterPassword(const std::string& password) {
    if (password.length() < MIN_MASTER_PASSWORD_LENGTH || 
        password.length() > MAX_MASTER_PASSWORD_LENGTH) {
        return false;
    }
    
    if (password.find('\0') != std::string::npos) {
        return false;
    }
    
    bool hasUpper = false, hasLower = false, hasDigit = false;
    
    for (char c : password) {
        if (std::isupper(static_cast<unsigned char>(c))) hasUpper = true;
        if (std::islower(static_cast<unsigned char>(c))) hasLower = true;
        if (std::isdigit(static_cast<unsigned char>(c))) hasDigit = true;
    }
    
    return hasUpper && hasLower && hasDigit;
}

bool InputValidator::validateFilePath(const std::string& path) {
    if (path.empty() || path.length() > 4096) {
        return false;
    }
    
    if (containsDirectoryTraversal(path)) {
        return false;
    }
    
    if (path.find("/etc/") == 0 || path.find("/sys/") == 0 || 
        path.find("/proc/") == 0 || path.find("/dev/") == 0) {
        return false;
    }
    
    return true;
}

std::string InputValidator::sanitize(const std::string& input) {
    std::string sanitized;
    sanitized.reserve(input.length());
    
    for (char c : input) {
        if (std::iscntrl(static_cast<unsigned char>(c)) && c != '\n' && c != '\t') {
            continue;
        }
        
        if (c == ';' || c == '|' || c == '&' || c == '$' || 
            c == '`' || c == '<' || c == '>') {
            continue;
        }
        
        sanitized += c;
    }
    
    return sanitized;
}

void InputValidator::requireValidServiceName(const std::string& service) {
    if (!validateServiceName(service)) {
        throw ValidationError("Invalid service name. Must be alphanumeric with dashes, dots, or underscores (max 256 chars)");
    }
}

void InputValidator::requireValidUsername(const std::string& username) {
    if (!validateUsername(username)) {
        throw ValidationError("Invalid username. Must be a valid email or alphanumeric string (max 256 chars)");
    }
}

void InputValidator::requireValidPassword(const std::string& password) {
    if (!validatePassword(password)) {
        throw ValidationError("Invalid password. Must be between 1 and 1024 characters");
    }
}

void InputValidator::requireValidMasterPassword(const std::string& password) {
    if (!validateMasterPassword(password)) {
        throw ValidationError("Invalid master password. Must be at least 8 characters with uppercase, lowercase, and digit");
    }
}

void InputValidator::requireValidFilePath(const std::string& path) {
    if (!validateFilePath(path)) {
        throw ValidationError("Invalid file path");
    }
}

