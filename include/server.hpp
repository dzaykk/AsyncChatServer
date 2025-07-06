#pragma once
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include "db_manager.hpp"

namespace chat {

    class Server {
    public:
        Server(boost::asio::io_context& io, unsigned short port,
            const std::string& cert_file, const std::string& key_file, const std::string& dh_file,
            DBManager& db);

        void run();

    private:
        boost::asio::ip::tcp::acceptor acceptor_;
        boost::asio::ssl::context ssl_ctx_;
        DBManager& db_;

        void do_accept();
    };

}