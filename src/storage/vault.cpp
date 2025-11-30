#include "vault.hpp"
#include "../crypto/crypto.hpp"
#include "../logging/logger.hpp"
#include "../validation/input_validator.hpp"
#include <stdexcept>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <chrono>
#include <iomanip>
#include <algorithm>

// Simple JSON helpers (lightweight, no external dependencies)
namespace json_helper {
    std::string escape(const std::string& str) {
        std::string result;
        for (char c : str) {
            switch (c) {
                case '"': result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\n': result += "\\n"; break;
                case '\r': result += "\\r"; break;
                case '\t': result += "\\t"; break;
                default: result += c; break;
            }
        }
        return result;
    }
    
    std::string unescape(const std::string& str) {
        std::string result;
        for (size_t i = 0; i < str.length(); ++i) {
            if (str[i] == '\\' && i + 1 < str.length()) {
                switch (str[i + 1]) {
                    case '"': result += '"'; i++; break;
                    case '\\': result += '\\'; i++; break;
                    case 'n': result += '\n'; i++; break;
                    case 'r': result += '\r'; i++; break;
                    case 't': result += '\t'; i++; break;
                    default: result += str[i]; break;
                }
            } else {
                result += str[i];
            }
        }
        return result;
    }
    
    std::string vectorToBase64(const std::vector<uint8_t>& data, Crypto& crypto) {
        return crypto.toBase64(data);
    }
    
    std::vector<uint8_t> base64ToVector(const std::string& str, Crypto& crypto) {
        return crypto.fromBase64(str);
    }
}

Vault::Vault() 
    : crypto_(std::make_unique<Crypto>())
    , isLocked_(true)
    , initialized_(false) {
    // Generate session ID
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << "session_" << timestamp << "_" << (rand() % 10000);
    sessionId_ = ss.str();
}

Vault::~Vault() {
    // Securely wipe sensitive data
    Crypto::secureWipe(masterPasswordHash_);
    Crypto::secureWipe(currentMasterPassword_);
    
    // Wipe all encrypted entries
    for (auto& pair : entries_) {
        Crypto::secureWipe(pair.second.encryptedUsername);
        Crypto::secureWipe(pair.second.encryptedPassword);
    }
    entries_.clear();
}

void Vault::setSecurePermissions(const std::string& filepath) {
    // Set file permissions to 0600 (owner read/write only)
    chmod(filepath.c_str(), S_IRUSR | S_IWUSR);
}

bool Vault::vaultExists(const std::string& filepath) {
    std::ifstream file(filepath);
    return file.good();
}

bool Vault::initialize(const std::string& filepath, const std::string& masterPassword) {
    try {
        InputValidator::requireValidFilePath(filepath);
        InputValidator::requireValidMasterPassword(masterPassword);
        
        filepath_ = filepath;
        
        // Check if vault already exists
        if (vaultExists(filepath)) {
            Logger::getInstance().log(LogLevel::ERROR, EventType::INIT, 
                "Vault already exists", sessionId_);
            return false;
        }
        
        // Hash the master password
        masterPasswordHash_ = crypto_->hash(masterPassword);
        
        // Store master password for encryption (wiped on lock)
        currentMasterPassword_ = masterPassword;
        
        // Initialize as unlocked and empty
        isLocked_ = false;
        initialized_ = true;
        
        // Save the vault
        if (!save()) {
            Logger::getInstance().log(LogLevel::ERROR, EventType::INIT, 
                "Failed to save initial vault", sessionId_);
            return false;
        }
        
        Logger::getInstance().log(LogLevel::INFO, EventType::INIT, 
            "Vault initialized successfully", sessionId_);
        return true;
    } catch (const ValidationError& e) {
        Logger::getInstance().log(LogLevel::ERROR, EventType::VALIDATION_ERROR, 
            e.what(), sessionId_);
        return false;
    } catch (const std::exception& e) {
        Logger::getInstance().log(LogLevel::ERROR, EventType::INIT, 
            "Vault initialization failed", sessionId_);
        return false;
    }
}

bool Vault::load(const std::string& filepath, const std::string& masterPassword) {
    try {
        InputValidator::requireValidFilePath(filepath);
        
        filepath_ = filepath;
        
        // Read the encrypted vault file
        std::ifstream file(filepath, std::ios::binary);
        if (!file.is_open()) {
            Logger::getInstance().log(LogLevel::ERROR, EventType::IO_ERROR, 
                "Failed to open vault file", sessionId_);
            return false;
        }
        
        std::string encryptedData((std::istreambuf_iterator<char>(file)),
                                  std::istreambuf_iterator<char>());
        file.close();
        
        if (encryptedData.empty()) {
            Logger::getInstance().log(LogLevel::ERROR, EventType::IO_ERROR, 
                "Vault file is empty", sessionId_);
            return false;
        }
        
        // Decrypt the vault data
        std::vector<uint8_t> encryptedBytes(encryptedData.begin(), encryptedData.end());
        std::string decryptedJson;
        
        try {
            decryptedJson = crypto_->decrypt(encryptedBytes, masterPassword);
        } catch (const std::exception& e) {
            Logger::getInstance().logAuthAttempt(false, sessionId_);
            return false;
        }
        
        // Parse the JSON
        if (!deserializeFromJson(decryptedJson)) {
            Logger::getInstance().log(LogLevel::ERROR, EventType::IO_ERROR, 
                "Failed to parse vault data", sessionId_);
            return false;
        }
        
        // Verify master password
        if (!crypto_->verifyHash(masterPassword, masterPasswordHash_)) {
            Logger::getInstance().logAuthAttempt(false, sessionId_);
            return false;
        }
        
        // Store master password for encryption (wiped on lock)
        currentMasterPassword_ = masterPassword;
        
        isLocked_ = false;
        initialized_ = true;
        
        Logger::getInstance().logAuthAttempt(true, sessionId_);
        return true;
    } catch (const ValidationError& e) {
        Logger::getInstance().log(LogLevel::ERROR, EventType::VALIDATION_ERROR, 
            e.what(), sessionId_);
        return false;
    } catch (const std::exception& e) {
        Logger::getInstance().log(LogLevel::ERROR, EventType::IO_ERROR, 
            "Vault loading failed", sessionId_);
        return false;
    }
}

bool Vault::save() {
    try {
        if (filepath_.empty() || currentMasterPassword_.empty()) {
            return false;
        }
        
        // Serialize to JSON
        std::string json = serializeToJson();
        
        // Encrypt the vault data with master password (matches load() decryption)
        std::vector<uint8_t> encryptedData = crypto_->encrypt(json, currentMasterPassword_);
        
        // Write to file
        std::ofstream file(filepath_, std::ios::binary);
        if (!file.is_open()) {
            Logger::getInstance().log(LogLevel::ERROR, EventType::IO_ERROR, 
                "Failed to open vault file for writing", sessionId_);
            return false;
        }
        
        file.write(reinterpret_cast<const char*>(encryptedData.data()), 
                   static_cast<std::streamsize>(encryptedData.size()));
        file.close();
        
        // Set secure permissions
        setSecurePermissions(filepath_);
        
        return true;
    } catch (const std::exception& e) {
        Logger::getInstance().log(LogLevel::ERROR, EventType::IO_ERROR, 
            "Vault saving failed", sessionId_);
        return false;
    }
}

bool Vault::unlock(const std::string& masterPassword) {
    if (!initialized_) {
        return false;
    }
    
    if (!crypto_->verifyHash(masterPassword, masterPasswordHash_)) {
        Logger::getInstance().logAuthAttempt(false, sessionId_);
        return false;
    }
    
    isLocked_ = false;
    Logger::getInstance().logAuthAttempt(true, sessionId_);
    return true;
}

void Vault::lock() {
    isLocked_ = true;
    Crypto::secureWipe(currentMasterPassword_);
    Logger::getInstance().log(LogLevel::INFO, EventType::LOCK, 
        "Vault locked", sessionId_);
}

void Vault::requireUnlocked() {
    if (isLocked_) {
        throw std::runtime_error("Authentication required");
    }
}

void Vault::setPassword(const std::string& service, const std::string& username, 
                        const std::string& password) {
    try {
        requireUnlocked();
        
        InputValidator::requireValidServiceName(service);
        InputValidator::requireValidUsername(username);
        InputValidator::requireValidPassword(password);
        
        // Encrypt username and password with master password
        // (encrypt() handles key derivation internally with stored salt)
        Entry entry;
        entry.encryptedUsername = crypto_->encrypt(username, currentMasterPassword_);
        entry.encryptedPassword = crypto_->encrypt(password, currentMasterPassword_);
        
        entries_[service] = entry;
        
        // Auto-save
        save();
        
        Logger::getInstance().logOperation(EventType::ADD_ENTRY, true, sessionId_);
    } catch (const ValidationError& e) {
        Logger::getInstance().log(LogLevel::ERROR, EventType::VALIDATION_ERROR, 
            e.what(), sessionId_);
        throw;
    } catch (const std::exception& e) {
        Logger::getInstance().logOperation(EventType::ADD_ENTRY, false, sessionId_);
        throw std::runtime_error("Failed to store password");
    }
}

std::string Vault::getPassword(const std::string& service, const std::string& username) {
    try {
        requireUnlocked();
        
        InputValidator::requireValidServiceName(service);
        InputValidator::requireValidUsername(username);
        
        auto it = entries_.find(service);
        if (it == entries_.end()) {
            Logger::getInstance().logOperation(EventType::GET_ENTRY, false, sessionId_);
            throw std::runtime_error("Service not found");
        }
        
        // Decrypt and verify username
        std::string decryptedUsername = crypto_->decrypt(it->second.encryptedUsername, currentMasterPassword_);
        if (decryptedUsername != username) {
            Logger::getInstance().logOperation(EventType::GET_ENTRY, false, sessionId_);
            throw std::runtime_error("Username does not match");
        }
        
        // Decrypt password
        std::string decryptedPassword = crypto_->decrypt(it->second.encryptedPassword, currentMasterPassword_);
        
        Logger::getInstance().logOperation(EventType::GET_ENTRY, true, sessionId_);
        return decryptedPassword;
    } catch (const ValidationError& e) {
        Logger::getInstance().log(LogLevel::ERROR, EventType::VALIDATION_ERROR, 
            e.what(), sessionId_);
        throw;
    } catch (const std::exception& e) {
        Logger::getInstance().logOperation(EventType::GET_ENTRY, false, sessionId_);
        throw std::runtime_error("Failed to retrieve password");
    }
}

std::pair<std::string, std::string> Vault::getCredentials(const std::string& service) {
    try {
        requireUnlocked();
        
        InputValidator::requireValidServiceName(service);
        
        auto it = entries_.find(service);
        if (it == entries_.end()) {
            Logger::getInstance().logOperation(EventType::GET_ENTRY, false, sessionId_);
            throw std::runtime_error("Service not found");
        }
        
        // Decrypt username and password
        std::string decryptedUsername = crypto_->decrypt(it->second.encryptedUsername, currentMasterPassword_);
        std::string decryptedPassword = crypto_->decrypt(it->second.encryptedPassword, currentMasterPassword_);
        
        Logger::getInstance().logOperation(EventType::GET_ENTRY, true, sessionId_);
        return {decryptedUsername, decryptedPassword};
    } catch (const ValidationError& e) {
        Logger::getInstance().log(LogLevel::ERROR, EventType::VALIDATION_ERROR, 
            e.what(), sessionId_);
        throw;
    } catch (const std::exception& e) {
        Logger::getInstance().logOperation(EventType::GET_ENTRY, false, sessionId_);
        throw std::runtime_error("Failed to retrieve credentials");
    }
}

bool Vault::deletePassword(const std::string& service, const std::string& username) {
    try {
        requireUnlocked();
        
        InputValidator::requireValidServiceName(service);
        InputValidator::requireValidUsername(username);
        
        auto it = entries_.find(service);
        if (it == entries_.end()) {
            return false;
        }
        
        // Decrypt and verify username
        std::string decryptedUsername = crypto_->decrypt(it->second.encryptedUsername, currentMasterPassword_);
        if (decryptedUsername != username) {
            return false;
        }
        
        // Securely wipe entry before deletion
        Crypto::secureWipe(it->second.encryptedUsername);
        Crypto::secureWipe(it->second.encryptedPassword);
        
        entries_.erase(it);
        
        // Auto-save
        save();
        
        Logger::getInstance().logOperation(EventType::DELETE_ENTRY, true, sessionId_);
        return true;
    } catch (const ValidationError& e) {
        Logger::getInstance().log(LogLevel::ERROR, EventType::VALIDATION_ERROR, 
            e.what(), sessionId_);
        return false;
    } catch (const std::exception& e) {
        Logger::getInstance().logOperation(EventType::DELETE_ENTRY, false, sessionId_);
        return false;
    }
}

std::vector<std::string> Vault::listServices() {
    try {
        requireUnlocked();
        
        std::vector<std::string> services;
        services.reserve(entries_.size());
        
        for (const auto& pair : entries_) {
            services.push_back(pair.first);
        }
        
        Logger::getInstance().logOperation(EventType::LIST_ENTRIES, true, sessionId_);
        return services;
    } catch (const std::exception& e) {
        Logger::getInstance().logOperation(EventType::LIST_ENTRIES, false, sessionId_);
        return {};
    }
}

std::string Vault::serializeToJson() {
    std::stringstream json;
    json << "{\n";
    json << "  \"version\": \"1.0\",\n";
    json << "  \"masterPasswordHash\": \"" << json_helper::escape(masterPasswordHash_) << "\",\n";
    json << "  \"entries\": [\n";
    
    bool first = true;
    for (const auto& pair : entries_) {
        if (!first) json << ",\n";
        first = false;
        
        json << "    {\n";
        json << "      \"service\": \"" << json_helper::escape(pair.first) << "\",\n";
        json << "      \"username\": \"" << json_helper::escape(crypto_->toBase64(pair.second.encryptedUsername)) << "\",\n";
        json << "      \"password\": \"" << json_helper::escape(crypto_->toBase64(pair.second.encryptedPassword)) << "\"\n";
        json << "    }";
    }
    
    json << "\n  ]\n";
    json << "}\n";
    
    return json.str();
}

bool Vault::deserializeFromJson(const std::string& json) {
    // Simple JSON parser for our specific format
    try {
        size_t pos = 0;
        
        // Extract masterPasswordHash
        pos = json.find("\"masterPasswordHash\":");
        if (pos == std::string::npos) return false;
        pos = json.find("\"", pos + 20);
        if (pos == std::string::npos) return false;
        pos++;
        size_t end = json.find("\"", pos);
        if (end == std::string::npos) return false;
        masterPasswordHash_ = json_helper::unescape(json.substr(pos, end - pos));
        
        // Extract entries
        pos = json.find("\"entries\":");
        if (pos == std::string::npos) return false;
        pos = json.find("[", pos);
        if (pos == std::string::npos) return false;
        
        entries_.clear();
        
        while (true) {
            pos = json.find("{", pos + 1);
            size_t entryEnd = json.find("}", pos);
            if (pos == std::string::npos || pos > json.find("]", pos)) break;
            
            // Extract service
            size_t servicePos = json.find("\"service\":", pos);
            if (servicePos == std::string::npos || servicePos > entryEnd) break;
            servicePos = json.find("\"", servicePos + 10);
            size_t serviceEnd = json.find("\"", servicePos + 1);
            std::string service = json_helper::unescape(json.substr(servicePos + 1, serviceEnd - servicePos - 1));
            
            // Extract username
            size_t userPos = json.find("\"username\":", pos);
            userPos = json.find("\"", userPos + 11);
            size_t userEnd = json.find("\"", userPos + 1);
            std::string usernameB64 = json_helper::unescape(json.substr(userPos + 1, userEnd - userPos - 1));
            
            // Extract password
            size_t passPos = json.find("\"password\":", pos);
            passPos = json.find("\"", passPos + 11);
            size_t passEnd = json.find("\"", passPos + 1);
            std::string passwordB64 = json_helper::unescape(json.substr(passPos + 1, passEnd - passPos - 1));
            
            // Create entry
            Entry entry;
            entry.encryptedUsername = crypto_->fromBase64(usernameB64);
            entry.encryptedPassword = crypto_->fromBase64(passwordB64);
            
            entries_[service] = entry;
            pos = entryEnd;
        }
        
        return true;
    } catch (...) {
        return false;
    }
}

