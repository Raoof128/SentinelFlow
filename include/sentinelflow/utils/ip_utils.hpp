#pragma once
#include <string>

#include "sentinelflow/utils/types.hpp"

namespace sf {

IPv4Address string_to_ip(const std::string& str);
bool ip_matches(IPv4Address addr, const std::string& pattern);  // "any" or specific IP
bool port_matches(uint16_t port, const std::string& pattern);   // "any" or specific port

}  // namespace sf
