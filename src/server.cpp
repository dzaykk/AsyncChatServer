#include "server.hpp"
#include "session.hpp"
#include "logger.hpp"

namespace chat {

    using boost::asio::ip::tcp;
    using SessionPtr = std::shared_ptr<Session>;

    Server::Server(boost::asio::io_context& io, unsigned short port,
        const std::string& cert_file, const std::string& key_file, const std::string& dh_file,
        DBManager& db)
        : acceptor_(io, tcp::endpoint(tcp::v4(), port)),
        ssl_ctx_(boost::asio::ssl::context::tls_server),
        db_(db)
    {
        ssl_ctx_.set_options(
            boost::asio::ssl::context::default_workarounds
            | boost::asio::ssl::context::no_sslv2
            | boost::asio::ssl::context::single_dh_use);

        ssl_ctx_.use_certificate_chain_file(cert_file);
        ssl_ctx_.use_private_key_file(key_file, boost::asio::ssl::context::pem);
        ssl_ctx_.use_tmp_dh_file(dh_file);
    }

    static std::unordered_map<std::string, SessionPtr> active_sessions_;
    static std::mutex session_mutex_;

    void Server::run() {
        do_accept();
    }

    void Server::do_accept() {
        acceptor_.async_accept(
            [this](boost::system::error_code ec, tcp::socket socket) {
                if (!ec) {
                    Logger::instance().log(LogLevel::INFO, "Client connected");
                    auto session = std::make_shared<Session>(
                        std::move(socket),
                        ssl_ctx_,
                        db_);
                    session->start();
                }
                else {
                    Logger::instance().log(LogLevel::PROTOCOL_ERROR, "Accept failed: " + ec.message());
                }
                do_accept();
            });
    }

}