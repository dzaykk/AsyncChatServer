#include "db_manager.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sstream>
#include <iomanip>
#include <stdexcept>

namespace chat {

    DBManager::DBManager(const std::string& db_file)
        : db_(nullptr)
    {
        if (sqlite3_open(db_file.c_str(), &db_) != SQLITE_OK) {
            throw std::runtime_error("Cannot open database: " + std::string(sqlite3_errmsg(db_)));
        }
        const char* create_sql =
            "CREATE TABLE IF NOT EXISTS users ("
            "username TEXT PRIMARY KEY,"
            "salt TEXT NOT NULL,"
            "hash TEXT NOT NULL"
            ");";
        exec(create_sql);
    }

    DBManager::~DBManager() {
        if (db_) {
            sqlite3_close(db_);
        }
    }

    void DBManager::exec(const std::string& sql) const {
        char* err = nullptr;
        if (sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err) != SQLITE_OK) {
            std::string e = err ? err : "unknown error";
            sqlite3_free(err);
            throw std::runtime_error("SQL error: " + e);
        }
    }

    std::string DBManager::generate_salt() {
        unsigned char buf[16];
        if (RAND_bytes(buf, sizeof(buf)) != 1) {
            throw std::runtime_error("RAND_bytes failed");
        }
        std::ostringstream oss;
        for (auto b : buf) {
            oss << std::hex << std::setw(2) << std::setfill('0') << int(b);
        }
        return oss.str();
    }

    std::string DBManager::sha256_hex(const std::string& data) {
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int len = 0;

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");

        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
            EVP_DigestUpdate(ctx, data.data(), data.size()) != 1 ||
            EVP_DigestFinal_ex(ctx, hash, &len) != 1)
        {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("SHA256 calculation failed");
        }
        EVP_MD_CTX_free(ctx);

        std::ostringstream oss;
        for (unsigned int i = 0; i < len; ++i) {
            oss << std::hex << std::setw(2) << std::setfill('0') << int(hash[i]);
        }
        return oss.str();
    }

    bool DBManager::register_user(const std::string& username, const std::string& password) {
        if (get_user(username).has_value()) {
            return false;
        }
        std::string salt = generate_salt();
        std::string hash = sha256_hex(salt + password);

        const char* insert_sql = "INSERT INTO users (username, salt, hash) VALUES (?, ?, ?);";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, insert_sql, -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("Failed to prepare insert statement");
        }
        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, salt.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, hash.c_str(), -1, SQLITE_TRANSIENT);

        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) {
            throw std::runtime_error("Failed to insert user");
        }
        return true;
    }

    std::optional<User> DBManager::get_user(const std::string& username) const {
        const char* select_sql = "SELECT salt, hash FROM users WHERE username = ?;";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, select_sql, -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("Failed to prepare select statement");
        }
        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);

        std::optional<User> user;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            User u;
            u.username = username;
            u.salt = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            u.hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            user = u;
        }
        sqlite3_finalize(stmt);
        return user;
    }

    bool DBManager::authenticate(const std::string& username, const std::string& password) const {
        auto opt = get_user(username);
        if (!opt.has_value()) return false;
        const User& u = *opt;
        std::string h2 = sha256_hex(u.salt + password);
        return h2 == u.hash;
    }

}