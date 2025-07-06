#include "server.hpp"
#include "logger.hpp"
#include "db_manager.hpp"
#include <boost/asio.hpp>
#include <iostream>

int main() {
    try {
        chat::Logger::instance().log(chat::LogLevel::INFO, "Server starting...");

        boost::asio::io_context io;
        chat::DBManager db("C:/Users/softd/source/repos/AsyncChatServer/thirdparty/sqlite/users.db");

        const std::string cert_file = "C:/Users/softd/source/repos/AsyncChatServer/certs/server.crt";
        const std::string key_file = "C:/Users/softd/source/repos/AsyncChatServer/certs/server.key";
        const std::string dh_file = "C:/Users/softd/source/repos/AsyncChatServer/certs/dh.pem";

        chat::Server server(io, 5555, cert_file, key_file, dh_file, db);
        server.run();

        io.run();
    }
    catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
    }

    return 0;
}