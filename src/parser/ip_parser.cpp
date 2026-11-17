#include "sentinelflow/parser/ip_parser.hpp"

#include <cstring>

#include <arpa/inet.h>

#include "sentinelflow/utils/byte_order.hpp"

namespace sf {

bool parse_ipv4(const uint8_t* data, uint32_t length, IPv4Header& header) {
    if (length < 20)
        return false;
    header.version = (data[0] >> 4) & 0x0F;
    header.ihl = data[0] & 0x0F;
    header.tos = data[1];
    header.total_length = read_be16(data + 2);
    header.identification = read_be16(data + 4);
    header.flags_fragment = read_be16(data + 6);
    header.ttl = data[8];
    header.protocol = data[9];
    header.checksum = read_be16(data + 10);
    std::memcpy(&header.src_ip, data + 12, 4);
    std::memcpy(&header.dst_ip, data + 16, 4);
    header.src_ip = ntohl(header.src_ip);
    header.dst_ip = ntohl(header.dst_ip);
    // IHL counts 32-bit words; the header must fit in the buffer we were given.
    return header.version == 4 && header.ihl >= 5 &&
           static_cast<uint32_t>(header.ihl) * 4 <= length;
}

}  // namespace sf
