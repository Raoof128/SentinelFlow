#include "sentinelflow/parser/ip_parser.hpp"

#include <cstring>

#include <arpa/inet.h>

namespace sf {

bool parse_ipv4(const uint8_t* data, uint32_t length, IPv4Header& header) {
    if (length < 20)
        return false;
    header.version = (data[0] >> 4) & 0x0F;
    header.ihl = data[0] & 0x0F;
    header.tos = data[1];
    header.total_length = ntohs(*reinterpret_cast<const uint16_t*>(data + 2));
    header.identification = ntohs(*reinterpret_cast<const uint16_t*>(data + 4));
    header.flags_fragment = ntohs(*reinterpret_cast<const uint16_t*>(data + 6));
    header.ttl = data[8];
    header.protocol = data[9];
    header.checksum = ntohs(*reinterpret_cast<const uint16_t*>(data + 10));
    std::memcpy(&header.src_ip, data + 12, 4);
    std::memcpy(&header.dst_ip, data + 16, 4);
    header.src_ip = ntohl(header.src_ip);
    header.dst_ip = ntohl(header.dst_ip);
    return (header.version == 4 && header.ihl >= 5);
}

}  // namespace sf
