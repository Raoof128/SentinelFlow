#include "sentinelflow/parser/ethernet_parser.hpp"

#include <cstring>

#include <arpa/inet.h>

namespace sf {

bool parse_ethernet(const uint8_t* data, uint32_t length, EthernetHeader& header) {
    if (length < 14)
        return false;
    std::memcpy(header.dst_mac.data(), data, 6);
    std::memcpy(header.src_mac.data(), data + 6, 6);
    header.ether_type = ntohs(*reinterpret_cast<const uint16_t*>(data + 12));
    return true;
}

}  // namespace sf
