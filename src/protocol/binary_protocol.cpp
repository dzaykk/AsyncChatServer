#include "binary_protocol.h"
#include <boost/asio.hpp>
#include <algorithm>

namespace chat_protocol {

    // Create a text message packet
    Packet BinaryProtocol::create_text_message(const std::string& message) {
        Packet packet;
        packet.header.type = MessageType::TextMessage;
        packet.payload.assign(message.begin(), message.end());
        packet.header.payload_length = static_cast<uint32_t>(packet.payload.size());
        packet.header.crc32 = calculate_crc32(packet.payload);
        return packet;
    }

    // Convert packet to byte vector for network transmission
    std::vector<uint8_t> BinaryProtocol::serialize(const Packet& packet) {
        std::vector<uint8_t> buffer;
        const uint8_t* header_ptr = reinterpret_cast<const uint8_t*>(&packet.header);
        buffer.insert(buffer.end(), header_ptr, header_ptr + sizeof(PacketHeader));
        buffer.insert(buffer.end(), packet.payload.begin(), packet.payload.end());
        return buffer;
    }

    // Convert byte vector back to packet
    Packet BinaryProtocol::deserialize(const std::vector<uint8_t>& buffer) {
        if (buffer.size() < sizeof(PacketHeader)) {
            throw std::runtime_error("Invalid packet size");
        }

        Packet packet;
        std::memcpy(&packet.header, buffer.data(), sizeof(PacketHeader));
        if (packet.header.payload_length > 0) {
            auto payload_start = buffer.begin() + sizeof(PacketHeader);
            packet.payload.assign(payload_start, payload_start + packet.header.payload_length);
        }
        return packet;
    }

    // Check packet validity using CRC32
    bool BinaryProtocol::validate(const Packet& packet) {
        return packet.header.crc32 == calculate_crc32(packet.payload);
    }

    // Asynchronously read a packet from socket
    template<typename Handler>
    void BinaryProtocol::async_read_packet(boost::asio::ip::tcp::socket& socket,
        std::vector<uint8_t>& buffer,
        Handler&& handler) {
        boost::asio::async_read(socket, boost::asio::buffer(buffer, sizeof(PacketHeader)),
            [&socket, &buffer, handler = std::forward<Handler>(handler)]
            (const boost::system::error_code& ec, size_t bytes_transferred) {
                if (ec) {
                    handler(ec, {});
                    return;
                }

                PacketHeader header;
                std::memcpy(&header, buffer.data(), sizeof(PacketHeader));

                if (header.payload_length > MAX_PAYLOAD_SIZE) {
                    handler(boost::system::errc::make_error_code(boost::system::errc::message_size), {});
                    return;
                }

                buffer.resize(sizeof(PacketHeader) + header.payload_length);
                boost::asio::async_read(socket, boost::asio::buffer(buffer.data() + sizeof(PacketHeader), header.payload_length),
                    [&buffer, handler = std::forward<Handler>(handler)]
                    (const boost::system::error_code& ec, size_t bytes_transferred) {
                        if (ec) {
                            handler(ec, {});
                            return;
                        }
                        handler(ec, deserialize(buffer));
                    });
            });
    }

    // Calculate CRC32 checksum for data
    uint32_t BinaryProtocol::calculate_crc32(const std::vector<uint8_t>& data) {
        uint32_t crc = 0xFFFFFFFF;
        for (uint8_t byte : data) {
            crc ^= byte;
            for (int i = 0; i < 8; ++i) {
                bool carry = crc & 1;
                crc >>= 1;
                if (carry) {
                    crc ^= 0xEDB88320;
                }
            }
        }
        return ~crc;
    }
}