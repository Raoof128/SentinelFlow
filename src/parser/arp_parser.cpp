#include "sentinelflow/parser/arp_parser.hpp"

#include <cstring>

#include <arpa/inet.h>

namespace sf {

bool parse_arp(const uint8_t* data, uint32_t length, ARPHeader& header) {
    if (length < 28)
        return false;
    header.hw_type = ntohs(*reinterpret_cast<const uint16_t*>(data));
    header.proto_type = ntohs(*reinterpret_cast<const uint16_t*>(data + 2));
    header.hw_size = data[4];
    header.proto_size = data[5];
    header.opcode = ntohs(*reinterpret_cast<const uint16_t*>(data + 6));
    std::memcpy(header.sender_mac.data(), data + 8, 6);
    std::memcpy(&header.sender_ip, data + 14, 4);
    header.sender_ip = ntohl(header.sender_ip);
    std::memcpy(header.target_mac.data(), data + 18, 6);
    std::memcpy(&header.target_ip, data + 24, 4);
    header.target_ip = ntohl(header.target_ip);
    return true;
}

}  // namespace sf
