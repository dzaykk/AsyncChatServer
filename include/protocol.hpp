#pragma once
#include <cstdint>
#include <vector>
#include <array>
#include <boost/crc.hpp>

namespace chat::proto {

    enum class Command : uint8_t {
        Register = 0x01,
        Login = 0x02,
        Message = 0x03,
        Ack = 0x04,
        Error = 0x05,
        FindPeer = 0x06,
        ChatRequest = 0x07,
        ChatAccept = 0x08,
        ChatDecline = 0x09,
        ExitChat = 0x0A
    };

    struct Packet {
        Command cmd;
        std::vector<uint8_t> body;
    };

    std::vector<uint8_t> serialize(const Packet& pkt);

    Packet deserialize(const std::vector<uint8_t>& buffer);

}