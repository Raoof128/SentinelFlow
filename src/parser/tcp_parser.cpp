#include "sentinelflow/parser/tcp_parser.hpp"

#include <arpa/inet.h>

namespace sf {

bool parse_tcp(const uint8_t* data, uint32_t length, TCPHeader& header) {
    if (length < 20)
        return false;
    header.src_port = ntohs(*reinterpret_cast<const uint16_t*>(data));
    header.dst_port = ntohs(*reinterpret_cast<const uint16_t*>(data + 2));
    header.seq_number = ntohl(*reinterpret_cast<const uint32_t*>(data + 4));
    header.ack_number = ntohl(*reinterpret_cast<const uint32_t*>(data + 8));
    header.data_offset = (data[12] >> 4) & 0x0F;
    header.flags = data[13];
    header.window_size = ntohs(*reinterpret_cast<const uint16_t*>(data + 14));
    header.checksum = ntohs(*reinterpret_cast<const uint16_t*>(data + 16));
    header.urgent_ptr = ntohs(*reinterpret_cast<const uint16_t*>(data + 18));
    return true;
}

}  // namespace sf
