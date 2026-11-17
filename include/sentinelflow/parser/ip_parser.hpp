#pragma once
#include "sentinelflow/parser/packet.hpp"

namespace sf {
bool parse_ipv4(const uint8_t* data, uint32_t length, IPv4Header& header);
}  // namespace sf
