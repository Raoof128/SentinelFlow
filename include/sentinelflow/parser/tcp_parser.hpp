#pragma once
#include "sentinelflow/parser/packet.hpp"

namespace sf {
bool parse_tcp(const uint8_t* data, uint32_t length, TCPHeader& header);
} // namespace sf
