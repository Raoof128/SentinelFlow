#pragma once
#include "sentinelflow/parser/packet.hpp"

namespace sf {
bool parse_udp(const uint8_t* data, uint32_t length, UDPHeader& header);
}  // namespace sf
