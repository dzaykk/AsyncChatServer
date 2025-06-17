#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <boost/asio.hpp>

namespace chat_protocol {

    // Protocol constants
    constexpr uint8_t PROTOCOL_VERSION = 1; // Current protocol version
    constexpr size_t MAX_PAYLOAD_SIZE = 1024 * 1024; // Max payload size (1MB)

    // Types of messages in the protocol
    enum class MessageType : uint8_t {
        AuthRequest = 1,  // Client authentication request
        AuthResponse,     // Server authentication response
        TextMessage,      // Regular chat message
        Logout,           // Client logout request
        ProtocolError = 0xFF // Error in protocol
    };

    // Disable struct padding to ensure header is exactly 12 bytes
    // Prevents alignment-dependent memory layouts
    // Essential when reading raw network bytes into struct
#pragma pack(push, 1)
    struct PacketHeader {
        uint8_t version = PROTOCOL_VERSION; // Protocol version
        MessageType type;                   // Message type
        uint32_t payload_length;            // Length of payload data
        uint32_t crc32;                     // CRC32 for validation
        uint16_t reserved = 0;              // Reserved for future use
    };
#pragma pack(pop)

    // Structure for a complete packet
    struct Packet {
        PacketHeader header;          // Packet header
        std::vector<uint8_t> payload; // Packet data
    };

    // Class for handling binary protocol operations
    class BinaryProtocol {
    public:
        // Disable copying to prevent misuse
        BinaryProtocol() = delete;
        BinaryProtocol(const BinaryProtocol&) = delete;
        BinaryProtocol& operator=(const BinaryProtocol&) = delete;

        // Create packets for specific message types
        static Packet create_text_message(const std::string& message);
        static Packet create_auth_request(const std::string& username, const std::string& password);

        // Serialize and deserialize packets
        static std::vector<uint8_t> serialize(const Packet& packet);
        static Packet deserialize(const std::vector<uint8_t>& buffer);

        // Validate packet integrity
        static bool validate(const Packet& packet);

        // Async read/write for network operations
        template<typename Handler>
        static void async_read_packet(boost::asio::ip::tcp::socket& socket,
            std::vector<uint8_t>& buffer,
            Handler&& handler);

        template<typename Handler>
        static void async_write_packet(boost::asio::ip::tcp::socket& socket,
            const Packet& packet,
            Handler&& handler);

    private:
        // Calculate CRC32 checksum for payload
        static uint32_t calculate_crc32(const std::vector<uint8_t>& data);
    };
}