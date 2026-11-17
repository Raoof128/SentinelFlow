#include "sentinelflow/parser/udp_parser.hpp"

#include <arpa/inet.h>

#include "sentinelflow/utils/byte_order.hpp"

namespace sf {

bool parse_udp(const uint8_t* data, uint32_t length, UDPHeader& header) {
    if (length < 8)
        return false;
    header.src_port = read_be16(data);
    header.dst_port = read_be16(data + 2);
    header.length = read_be16(data + 4);
    header.checksum = read_be16(data + 6);
    return true;
}

}  // namespace sf
