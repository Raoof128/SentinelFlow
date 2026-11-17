#include "sentinelflow/parser/arp_parser.hpp"

#include <cstring>

#include <arpa/inet.h>

#include "sentinelflow/utils/byte_order.hpp"

namespace sf {

bool parse_arp(const uint8_t* data, uint32_t length, ARPHeader& header) {
    if (length < 28)
        return false;
    header.hw_type = read_be16(data);
    header.proto_type = read_be16(data + 2);
    header.hw_size = data[4];
    header.proto_size = data[5];
    header.opcode = read_be16(data + 6);
    std::memcpy(header.sender_mac.data(), data + 8, 6);
    std::memcpy(&header.sender_ip, data + 14, 4);
    header.sender_ip = ntohl(header.sender_ip);
    std::memcpy(header.target_mac.data(), data + 18, 6);
    std::memcpy(&header.target_ip, data + 24, 4);
    header.target_ip = ntohl(header.target_ip);
    return true;
}

}  // namespace sf
