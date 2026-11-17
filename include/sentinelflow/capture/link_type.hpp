#pragma once
#include <string>

#include <pcap.h>

namespace sf {

/// Check that `handle` delivers Ethernet frames (DLT_EN10MB), the only link layer the parsers
/// understand. If it does not, print an error naming `source` and the link type found, and
/// return false. Other link types (loopback, raw IP, 802.11, Linux cooked, ...) have different
/// headers, and reading them as Ethernet produces nonsense without any error.
bool require_ethernet_link(pcap_t* handle, const std::string& source);

}  // namespace sf
