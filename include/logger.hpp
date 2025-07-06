#pragma once
#include <string>
#include <fstream>
#include <mutex>

namespace chat {

    enum class LogLevel {
        INFO,
        WARNING,
        PROTOCOL_ERROR
    };

    class Logger {
    public:
        explicit Logger(const std::string& file);
        ~Logger();

        void log(LogLevel level, const std::string& message);

        static Logger& instance();

        static void log_info(const std::string& msg);
        static void log_error(const std::string& msg);

    private:
        std::ofstream out_;
        std::mutex mutex_;

        std::string level_to_string(LogLevel level);
        std::string timestamp();
    };

}