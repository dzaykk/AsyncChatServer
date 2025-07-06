#pragma once
#include <string>
#include <optional>
#include <sqlite3.h>

namespace chat {

    struct User {
        std::string username;
        std::string salt;
        std::string hash;
    };

    class DBManager {
    public:
        explicit DBManager(const std::string& db_file);
        ~DBManager();

        bool register_user(const std::string& username, const std::string& password);

        bool authenticate(const std::string& username, const std::string& password) const;

        std::optional<User> get_user(const std::string& username) const;

    private:
        sqlite3* db_;

        static std::string generate_salt();

        static std::string sha256_hex(const std::string& data);

        void exec(const std::string& sql) const;
    };

}