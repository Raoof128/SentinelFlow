#pragma once
#include "sentinelflow/parser/packet.hpp"

namespace sf {
bool parse_ethernet(const uint8_t* data, uint32_t length, EthernetHeader& header);
}  // namespace sf
