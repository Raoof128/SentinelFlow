#pragma once
#include "sentinelflow/parser/packet.hpp"

namespace sf {
bool parse_arp(const uint8_t* data, uint32_t length, ARPHeader& header);
}  // namespace sf
