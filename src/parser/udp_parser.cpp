#include "sentinelflow/parser/udp_parser.hpp"

#include <arpa/inet.h>

namespace sf {

bool parse_udp(const uint8_t* data, uint32_t length, UDPHeader& header) {
    if (length < 8)
        return false;
    header.src_port = ntohs(*reinterpret_cast<const uint16_t*>(data));
    header.dst_port = ntohs(*reinterpret_cast<const uint16_t*>(data + 2));
    header.length = ntohs(*reinterpret_cast<const uint16_t*>(data + 4));
    header.checksum = ntohs(*reinterpret_cast<const uint16_t*>(data + 6));
    return true;
}

}  // namespace sf
