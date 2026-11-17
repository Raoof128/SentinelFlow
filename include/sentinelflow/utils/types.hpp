#pragma once
#include <array>
#include <chrono>
#include <cstdint>
#include <string>

namespace sf {

using MacAddress = std::array<uint8_t, 6>;
using IPv4Address = uint32_t;

std::string ip_to_string(IPv4Address addr);
std::string mac_to_string(const MacAddress& addr);

}  // namespace sf
