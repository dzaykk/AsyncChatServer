#include <iostream>
#include "logger.hpp"
#include <chrono>
#include <iomanip>
#include <ctime>

namespace chat {

    Logger::Logger(const std::string& file) {
        out_.open(file, std::ios::app);
        if (!out_.is_open()) {
            throw std::runtime_error("Cannot open log file");
        }
    }

    Logger::~Logger() {
        if (out_.is_open()) {
            out_.close();
        }
    }

    Logger& Logger::instance() {
        static Logger logger("C:/Users/softd/source/repos/AsyncChatServer/logs/server.log");
        return logger;
    }

    std::string Logger::level_to_string(LogLevel level) {
        switch (level) {
        case LogLevel::INFO:    return "INFO";
        case LogLevel::WARNING: return "WARN";
        case LogLevel::PROTOCOL_ERROR:   return "ERR ";
        default: return "UNK";
        }
    }

    std::string Logger::timestamp() {
        using namespace std::chrono;
        auto now = system_clock::now();
        std::time_t t = system_clock::to_time_t(now);
        std::tm tm{};
#if defined(_WIN32)
        localtime_s(&tm, &t);
#else
        localtime_r(&t, &tm);
#endif
        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
        return oss.str();
    }

    void Logger::log(LogLevel level, const std::string& message) {
        std::lock_guard<std::mutex> lock(mutex_);
        out_ << "[" << timestamp() << "] [" << level_to_string(level) << "] " << message << std::endl;
    }

    void Logger::log_info(const std::string& msg) {
        instance().log(LogLevel::INFO, msg);
    }

    void Logger::log_error(const std::string& msg) {
        instance().log(LogLevel::PROTOCOL_ERROR, msg);
    }
}