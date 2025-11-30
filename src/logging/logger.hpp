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
    
    void initialize(const std::string& logPath);
    
    void log(LogLevel level, EventType event, const std::string& message);
    void log(LogLevel level, EventType event, const std::string& message, const std::string& sessionId);
    void log(LogLevel level, EventType event, const std::string& message, 
             const std::string& sessionId, const std::string& ipAddress);
    
    void logAuthAttempt(bool success, const std::string& sessionId, 
                        const std::string& ipAddress = "127.0.0.1");
    void logOperation(EventType event, bool success, const std::string& sessionId,
                      const std::string& ipAddress = "127.0.0.1");
    
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

#endif

