#include "sentinelflow/parser/icmp_parser.hpp"
#include <arpa/inet.h>

namespace sf {

bool parse_icmp(const uint8_t* data, uint32_t length, ICMPHeader& header) {
    if (length < 8) return false;
    header.type       = data[0];
    header.code       = data[1];
    header.checksum   = ntohs(*reinterpret_cast<const uint16_t*>(data + 2));
    header.identifier = ntohs(*reinterpret_cast<const uint16_t*>(data + 4));
    header.sequence   = ntohs(*reinterpret_cast<const uint16_t*>(data + 6));
    return true;
}

} // namespace sf
