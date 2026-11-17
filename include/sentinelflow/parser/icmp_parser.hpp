#pragma once
#include "sentinelflow/parser/packet.hpp"

namespace sf {
bool parse_icmp(const uint8_t* data, uint32_t length, ICMPHeader& header);
}  // namespace sf
