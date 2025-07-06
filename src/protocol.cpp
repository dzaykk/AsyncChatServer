#include "protocol.hpp"
#include <stdexcept>
#include <cstring>

namespace chat::proto {

    static constexpr std::array<uint8_t, 4> MAGIC = { 'M','A','G','C' };

    std::vector<uint8_t> serialize(const Packet& pkt) {
        uint16_t len = static_cast<uint16_t>(pkt.body.size());
        std::vector<uint8_t> out;
        out.reserve(4 + 1 + 2 + len + 4);

        out.insert(out.end(), MAGIC.begin(), MAGIC.end());
        out.push_back(static_cast<uint8_t>(pkt.cmd));
        out.push_back(uint8_t((len >> 8) & 0xFF));
        out.push_back(uint8_t(len & 0xFF));
        out.insert(out.end(), pkt.body.begin(), pkt.body.end());

        boost::crc_32_type crc;
        crc.process_bytes(out.data(), out.size());
        uint32_t checksum = crc.checksum();
        out.push_back(uint8_t((checksum >> 24) & 0xFF));
        out.push_back(uint8_t((checksum >> 16) & 0xFF));
        out.push_back(uint8_t((checksum >> 8) & 0xFF));
        out.push_back(uint8_t(checksum & 0xFF));

        return out;
    }

    Packet deserialize(const std::vector<uint8_t>& buffer) {
        if (buffer.size() < 4 + 1 + 2 + 4)
            throw std::runtime_error("Buffer too small for header");

        size_t pos = 0;
        if (!std::equal(MAGIC.begin(), MAGIC.end(), buffer.begin()))
            throw std::runtime_error("Invalid magic header");
        pos += 4;

        Command cmd = static_cast<Command>(buffer[pos++]);

        uint16_t len = (uint16_t(buffer[pos]) << 8) | uint16_t(buffer[pos + 1]);
        pos += 2;

        if (buffer.size() < pos + len + 4)
            throw std::runtime_error("Buffer too small for body");

        size_t crc_pos = pos + len;
        boost::crc_32_type crc;
        crc.process_bytes(buffer.data(), crc_pos);
        uint32_t expected = crc.checksum();
        uint32_t actual =
            (uint32_t(buffer[crc_pos]) << 24) |
            (uint32_t(buffer[crc_pos + 1]) << 16) |
            (uint32_t(buffer[crc_pos + 2]) << 8) |
            uint32_t(buffer[crc_pos + 3]);
        if (expected != actual)
            throw std::runtime_error("CRC mismatch");

        std::vector<uint8_t> body(buffer.begin() + pos, buffer.begin() + pos + len);
        return Packet{ cmd, std::move(body) };
    }

}