#include "sentinelflow/parser/tcp_parser.hpp"

#include <arpa/inet.h>

#include "sentinelflow/utils/byte_order.hpp"

namespace sf {

bool parse_tcp(const uint8_t* data, uint32_t length, TCPHeader& header) {
    if (length < 20)
        return false;
    header.src_port = read_be16(data);
    header.dst_port = read_be16(data + 2);
    header.seq_number = read_be32(data + 4);
    header.ack_number = read_be32(data + 8);
    header.data_offset = (data[12] >> 4) & 0x0F;
    header.flags = data[13];
    header.window_size = read_be16(data + 14);
    header.checksum = read_be16(data + 16);
    header.urgent_ptr = read_be16(data + 18);
    return true;
}

}  // namespace sf
