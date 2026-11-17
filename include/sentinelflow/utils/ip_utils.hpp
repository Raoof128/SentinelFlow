#pragma once
#include <optional>
#include <string>

#include "sentinelflow/utils/types.hpp"

namespace sf {

/// Parse a dotted-quad IPv4 address. Returns 0 on failure, which is also the address 0.0.0.0, so
/// use parse_ipv4_address when the difference matters.
IPv4Address string_to_ip(const std::string& str);

/// Strictly parse a dotted-quad IPv4 address.
std::optional<IPv4Address> parse_ipv4_address(const std::string& str);

/// An IPv4 network: `addr & mask == network` for every member address.
struct Ipv4Network {
    IPv4Address network;
    IPv4Address mask;
};

/// Parse "a.b.c.d/len" with len in 0..32. Host bits in the address are cleared.
std::optional<Ipv4Network> parse_ipv4_cidr(const std::string& str);

/// True for "any", a dotted-quad address, or an IPv4 CIDR block.
bool is_valid_ip_pattern(const std::string& pattern);

/// True for "any" or a decimal port in 0..65535 (no sign, no spaces, no ranges).
bool is_valid_port_pattern(const std::string& pattern);

/// Match an address against "any", a single address, or a CIDR block. A malformed pattern
/// matches nothing.
bool ip_matches(IPv4Address addr, const std::string& pattern);

/// Match a port against "any" or a single port. A malformed pattern matches nothing.
bool port_matches(uint16_t port, const std::string& pattern);

}  // namespace sf
