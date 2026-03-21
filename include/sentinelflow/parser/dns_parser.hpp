#pragma once
#include "sentinelflow/parser/packet.hpp"

namespace sf {
bool parse_dns(const uint8_t* data, uint32_t length, DNSHeader& header);
} // namespace sf
