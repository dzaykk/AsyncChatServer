#pragma once
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include "protocol.hpp"
#include "db_manager.hpp"
#include <vector>
#include <string>
#include <unordered_map>
#include <memory>
#include <mutex>

namespace chat {

    using boost::asio::ip::tcp;
    namespace ssl = boost::asio::ssl;

    class Session : public std::enable_shared_from_this<Session> {
    public:
        Session(tcp::socket&& socket, ssl::context& ssl_ctx, DBManager& db);
        void start();

    private:
        void do_handshake();
        void do_read();
        void handle_packet(const proto::Packet& packet);
        void send_packet(const proto::Packet& packet);

        void handle_register_or_login(proto::Command cmd, const std::string& body);
        void handle_find_peer(const std::string& peer_name);
        void handle_chat_request_response(bool accepted);
        void handle_chat_message(const std::string& body);

        void send_chat_request_to_peer(const std::string& peer_name);
        void notify_peer_disconnected();

        ssl::stream<tcp::socket> stream_;
        DBManager& db_;
        std::vector<uint8_t> buffer_;
        static constexpr size_t max_length = 8192;

        std::string username_;
        std::string current_peer_;
        bool logged_in_ = false;
        bool in_chat_ = false;

        static std::mutex g_mutex;
        static std::unordered_map<std::string, std::shared_ptr<Session>> g_active_users;
    };

}