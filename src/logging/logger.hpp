#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <string>
#include <fstream>
#include <mutex>

enum class LogLevel {
    INFO,
    WARNING,
    ERROR,
    SECURITY
};

enum class EventType {
    INIT,
    UNLOCK_SUCCESS,
    UNLOCK_FAILURE,
    ADD_ENTRY,
    GET_ENTRY,
    DELETE_ENTRY,
    LIST_ENTRIES,
    LOCK,
    VALIDATION_ERROR,
    IO_ERROR,
    CRYPTO_ERROR
};

class Logger {
public:
    static Logger& getInstance();
    
    // Initialize logger with log file path
    void initialize(const std::string& logPath);
    
    // Log an event
    void log(LogLevel level, EventType event, const std::string& message);
    void log(LogLevel level, EventType event, const std::string& message, const std::string& sessionId);
    
    // Security-specific logging
    void logAuthAttempt(bool success, const std::string& sessionId);
    void logOperation(EventType event, bool success, const std::string& sessionId);
    
    // Disable copying
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

private:
    Logger();
    ~Logger();
    
    std::string eventTypeToString(EventType event);
    std::string logLevelToString(LogLevel level);
    std::string getCurrentTimestamp();
    
    std::ofstream logFile_;
    std::recursive_mutex mutex_;
    bool initialized_;
};

#endif // LOGGER_HPP

