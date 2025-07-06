#include "session.hpp"
#include "logger.hpp"
#include <iostream>

namespace chat {

    std::mutex Session::g_mutex;
    std::unordered_map<std::string, std::shared_ptr<Session>> Session::g_active_users;

    Session::Session(tcp::socket&& socket, ssl::context& ssl_ctx, DBManager& db)
        : stream_(std::move(socket), ssl_ctx), db_(db) {
        buffer_.resize(max_length);
    }

    void Session::start() {
        do_handshake();
    }

    void Session::do_handshake() {
        auto self = shared_from_this();
        stream_.async_handshake(ssl::stream_base::server,
            [this, self](const boost::system::error_code& ec) {
                if (!ec) {
                    Logger::log_info("SSL handshake complete");
                    do_read();
                }
                else {
                    Logger::log_error("Handshake failed: " + ec.message());
                }
            });
    }

    void Session::do_read() {
        auto self = shared_from_this();
        stream_.async_read_some(boost::asio::buffer(buffer_),
            [this, self](boost::system::error_code ec, std::size_t len) {
                if (!ec) {
                    try {
                        std::vector<uint8_t> data(buffer_.begin(), buffer_.begin() + len);
                        proto::Packet pkt = proto::deserialize(data);
                        handle_packet(pkt);
                    }
                    catch (const std::exception& ex) {
                        Logger::log_error(std::string("Deserialize failed: ") + ex.what());
                    }
                    do_read();
                }
                else {
                    Logger::log_info("Client disconnected: " + username_);
                    std::scoped_lock lock(g_mutex);
                    if (!username_.empty()) g_active_users.erase(username_);
                    if (!current_peer_.empty()) notify_peer_disconnected();
                }
            });
    }

    void Session::handle_packet(const proto::Packet& packet) {
        using proto::Command;

        std::string body(packet.body.begin(), packet.body.end());

        switch (packet.cmd) {
        case Command::Register:
        case Command::Login:
            handle_register_or_login(packet.cmd, body);
            break;

        case Command::FindPeer:
            handle_find_peer(body);
            break;

        case Command::Message:
            handle_chat_message(body);
            break;

        case Command::Ack:
            handle_chat_request_response(true);
            break;

        case Command::Error:
            handle_chat_request_response(false);
            break;

        default:
            send_packet({ Command::Error, { 'U','N','K','N' } });
        }
    }

    void Session::handle_register_or_login(proto::Command cmd, const std::string& body) {
        auto pos = body.find(':');
        if (pos == std::string::npos) {
            send_packet({ proto::Command::Error, {'B','A','D','F'} });
            return;
        }

        std::string user = body.substr(0, pos);
        std::string pass = body.substr(pos + 1);

        bool success = (cmd == proto::Command::Register)
            ? db_.register_user(user, pass)
            : db_.authenticate(user, pass);

        proto::Packet resp;
        if (success) {
            username_ = user;
            logged_in_ = true;
            {
                std::scoped_lock lock(g_mutex);
                g_active_users[username_] = shared_from_this();
            }
            resp.cmd = proto::Command::Ack;
            resp.body = { 'O','K' };
        }
        else {
            resp.cmd = proto::Command::Error;
            resp.body = (cmd == proto::Command::Register)
                ? std::vector<uint8_t>{ 'U', 'S', 'E', 'R', '!' }
            : std::vector<uint8_t>{ 'A','U','T','H','!' };
        }

        send_packet(resp);
    }

    void Session::handle_find_peer(const std::string& peer_name) {
        if (!logged_in_) {
            send_packet({ proto::Command::Error, { 'N','O','L','O','G' } });
            return;
        }

        if (peer_name == username_) {
            send_packet({ proto::Command::Error, { 'S','E','L','F' } });
            return;
        }

        std::shared_ptr<Session> peer;
        {
            std::scoped_lock lock(g_mutex);
            auto it = g_active_users.find(peer_name);
            if (it != g_active_users.end()) {
                peer = it->second;
            }
        }

        if (peer) {
            current_peer_ = peer_name;
            peer->send_chat_request_to_peer(username_);
        }
        else {
            send_packet({ proto::Command::Error, { 'N','O','P','E' } });
        }
    }

    void Session::send_chat_request_to_peer(const std::string& from_user) {
        proto::Packet req;
        req.cmd = proto::Command::FindPeer;
        req.body.assign(from_user.begin(), from_user.end());
        send_packet(req);
    }

    void Session::handle_chat_request_response(bool accepted) {
        if (current_peer_.empty()) return;

        std::shared_ptr<Session> peer;
        {
            std::scoped_lock lock(g_mutex);
            auto it = g_active_users.find(current_peer_);
            if (it != g_active_users.end()) {
                peer = it->second;
            }
        }

        if (peer) {
            if (accepted) {
                in_chat_ = true;
                peer->in_chat_ = true;
                peer->current_peer_ = username_;

                peer->send_packet({ proto::Command::Ack, { 'C','H','A','T' } });
                send_packet({ proto::Command::Ack, { 'C','H','A','T' } });
            }
            else {
                peer->send_packet({ proto::Command::Error, { 'D','E','N','Y' } });
                current_peer_.clear();
            }
        }
    }

    void Session::handle_chat_message(const std::string& body) {
        if (!logged_in_ || !in_chat_ || current_peer_.empty()) {
            send_packet({ proto::Command::Error, { 'N','O','C','H','A','T' } });
            return;
        }

        if (body == "/exit") {
            send_packet({ proto::Command::Ack, { 'B','Y','E' } });

            std::shared_ptr<Session> peer;
            {
                std::scoped_lock lock(g_mutex);
                auto it = g_active_users.find(current_peer_);
                if (it != g_active_users.end()) {
                    peer = it->second;
                }
            }

            if (peer) {
                peer->send_packet({ proto::Command::Error, { 'E','X','I','T' } });
                peer->in_chat_ = false;
                peer->current_peer_.clear();
            }

            in_chat_ = false;
            current_peer_.clear();
            return;
        }

        std::shared_ptr<Session> peer;
        {
            std::scoped_lock lock(g_mutex);
            auto it = g_active_users.find(current_peer_);
            if (it != g_active_users.end()) {
                peer = it->second;
            }
        }

        if (peer) {
            std::string msg = username_ + ": " + body;
            proto::Packet pkt{ proto::Command::Message, std::vector<uint8_t>(msg.begin(), msg.end()) };
            peer->send_packet(pkt);
            send_packet({ proto::Command::Ack, { 'O','K' } });
        }
        else {
            send_packet({ proto::Command::Error, { 'L','O','S','T' } });
        }
    }

    void Session::send_packet(const proto::Packet& packet) {
        auto data = proto::serialize(packet);
        auto self = shared_from_this();
        boost::asio::async_write(stream_, boost::asio::buffer(data),
            [this, self](boost::system::error_code ec, std::size_t) {
                if (ec) {
                    Logger::log_error("Send error: " + ec.message());
                }
            });
    }

    void Session::notify_peer_disconnected() {
        std::shared_ptr<Session> peer;
        {
            std::scoped_lock lock(g_mutex);
            auto it = g_active_users.find(current_peer_);
            if (it != g_active_users.end()) {
                peer = it->second;
            }
        }

        if (peer) {
            peer->send_packet({ proto::Command::Error, { 'E','X','I','T' } });
            peer->in_chat_ = false;
            peer->current_peer_.clear();
        }

        in_chat_ = false;
        current_peer_.clear();
    }

}