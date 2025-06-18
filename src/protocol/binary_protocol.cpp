#include "binary_protocol.h"
#include <boost/asio.hpp>
#include <algorithm>

namespace protocol {

    // Create a text message packet
    Packet BinaryProtocol::create_text_message(const std::string& message) {
        Packet packet;
        packet.header.type = MessageType::TextMessage;
        packet.payload.assign(message.begin(), message.end());
        packet.header.payload_length = static_cast<uint32_t>(packet.payload.size());
        packet.header.crc32 = calculate_crc32(packet.payload);
        return packet;
    }

    // Create an authentication request packet
    Packet BinaryProtocol::create_auth_request(const std::string& username, const std::string& password) {
        Packet packet;
        packet.header.type = MessageType::AuthRequest;
        std::string payload = username + "|" + password;
        packet.payload.assign(payload.begin(), payload.end());
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