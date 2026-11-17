#include "sentinelflow/parser/icmp_parser.hpp"

#include <arpa/inet.h>

#include "sentinelflow/utils/byte_order.hpp"

namespace sf {

bool parse_icmp(const uint8_t* data, uint32_t length, ICMPHeader& header) {
    if (length < 8)
        return false;
    header.type = data[0];
    header.code = data[1];
    header.checksum = read_be16(data + 2);
    header.identifier = read_be16(data + 4);
    header.sequence = read_be16(data + 6);
    return true;
}

}  // namespace sf
