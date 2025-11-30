#include "logger.hpp"
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <sys/stat.h>

Logger::Logger() : initialized_(false) {}

Logger::~Logger() {
    if (logFile_.is_open()) {
        logFile_.close();
    }
}

Logger& Logger::getInstance() {
    static Logger instance;
    return instance;
}

void Logger::initialize(const std::string& logPath) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    if (initialized_) {
        return;
    }
    
    logFile_.open(logPath, std::ios::app);
    if (!logFile_.is_open()) {
        std::cerr << "Warning: Could not open log file: " << logPath << std::endl;
        return;
    }
    
    chmod(logPath.c_str(), S_IRUSR | S_IWUSR);
    
    initialized_ = true;
    log(LogLevel::INFO, EventType::INIT, "Logger initialized");
}

std::string Logger::getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
    ss << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return ss.str();
}

std::string Logger::logLevelToString(LogLevel level) {
    switch (level) {
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARNING: return "WARNING";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::SECURITY: return "SECURITY";
        default: return "UNKNOWN";
    }
}

std::string Logger::eventTypeToString(EventType event) {
    switch (event) {
        case EventType::INIT: return "INIT";
        case EventType::UNLOCK_SUCCESS: return "UNLOCK_SUCCESS";
        case EventType::UNLOCK_FAILURE: return "UNLOCK_FAILURE";
        case EventType::ADD_ENTRY: return "ADD_ENTRY";
        case EventType::GET_ENTRY: return "GET_ENTRY";
        case EventType::DELETE_ENTRY: return "DELETE_ENTRY";
        case EventType::LIST_ENTRIES: return "LIST_ENTRIES";
        case EventType::LOCK: return "LOCK";
        case EventType::VALIDATION_ERROR: return "VALIDATION_ERROR";
        case EventType::IO_ERROR: return "IO_ERROR";
        case EventType::CRYPTO_ERROR: return "CRYPTO_ERROR";
        default: return "UNKNOWN";
    }
}

void Logger::log(LogLevel level, EventType event, const std::string& message) {
    log(level, event, message, "");
}

void Logger::log(LogLevel level, EventType event, const std::string& message, const std::string& sessionId) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    std::stringstream logEntry;
    logEntry << "[" << getCurrentTimestamp() << "] "
             << "[" << logLevelToString(level) << "] "
             << "[" << eventTypeToString(event) << "] ";
    
    if (!sessionId.empty()) {
        logEntry << "[Session: " << sessionId << "] ";
    }
    
    logEntry << message;
    
    if (initialized_ && logFile_.is_open()) {
        logFile_ << logEntry.str() << std::endl;
        logFile_.flush();
    }
    
    if (level == LogLevel::SECURITY || level == LogLevel::ERROR) {
        std::cerr << logEntry.str() << std::endl;
    }
}

void Logger::logAuthAttempt(bool success, const std::string& sessionId) {
    if (success) {
        log(LogLevel::SECURITY, EventType::UNLOCK_SUCCESS, 
            "Authentication successful", sessionId);
    } else {
        log(LogLevel::SECURITY, EventType::UNLOCK_FAILURE, 
            "Authentication failed", sessionId);
    }
}

void Logger::logOperation(EventType event, bool success, const std::string& sessionId) {
    LogLevel level = success ? LogLevel::INFO : LogLevel::ERROR;
    std::string message = success ? "Operation completed" : "Operation failed";
    log(level, event, message, sessionId);
}

