#include "sentinelflow/utils/ip_utils.hpp"

#include <cstdlib>

#include <arpa/inet.h>

namespace sf {

namespace {

// Parse a string of 1..max_digits decimal digits (no sign, no spaces) into a value <= max_value.
std::optional<uint32_t> parse_decimal(const std::string& str, size_t max_digits,
                                      uint32_t max_value) {
    if (str.empty() || str.size() > max_digits)
        return std::nullopt;
    uint32_t value = 0;
    for (char c : str) {
        if (c < '0' || c > '9')
            return std::nullopt;
        value = value * 10 + static_cast<uint32_t>(c - '0');
    }
    if (value > max_value)
        return std::nullopt;
    return value;
}

}  // namespace

IPv4Address string_to_ip(const std::string& str) {
    return parse_ipv4_address(str).value_or(0);
}

std::optional<IPv4Address> parse_ipv4_address(const std::string& str) {
    struct in_addr addr;
    if (inet_pton(AF_INET, str.c_str(), &addr) != 1)
        return std::nullopt;
    return ntohl(addr.s_addr);
}

std::optional<Ipv4Network> parse_ipv4_cidr(const std::string& str) {
    const auto slash = str.find('/');
    if (slash == std::string::npos)
        return std::nullopt;
    auto addr = parse_ipv4_address(str.substr(0, slash));
    auto prefix = parse_decimal(str.substr(slash + 1), 2, 32);
    if (!addr || !prefix)
        return std::nullopt;
    // A shift by 32 is undefined, so /0 is handled separately.
    const IPv4Address mask = (*prefix == 0) ? 0 : (0xFFFFFFFFu << (32 - *prefix));
    return Ipv4Network{*addr & mask, mask};
}

bool is_valid_ip_pattern(const std::string& pattern) {
    if (pattern == "any")
        return true;
    if (pattern.find('/') != std::string::npos)
        return parse_ipv4_cidr(pattern).has_value();
    return parse_ipv4_address(pattern).has_value();
}

bool is_valid_port_pattern(const std::string& pattern) {
    return pattern == "any" || parse_decimal(pattern, 5, 65535).has_value();
}

bool ip_matches(IPv4Address addr, const std::string& pattern) {
    if (pattern == "any")
        return true;
    if (pattern.find('/') != std::string::npos) {
        auto net = parse_ipv4_cidr(pattern);
        return net && (addr & net->mask) == net->network;
    }
    auto exact = parse_ipv4_address(pattern);
    return exact && addr == *exact;
}

bool port_matches(uint16_t port, const std::string& pattern) {
    if (pattern == "any")
        return true;
    auto value = parse_decimal(pattern, 5, 65535);
    return value && port == *value;
}

}  // namespace sf
