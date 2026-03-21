#include "sentinelflow/utils/ip_utils.hpp"
#include <arpa/inet.h>

namespace sf {

IPv4Address string_to_ip(const std::string& str) {
    struct in_addr addr;
    if (inet_pton(AF_INET, str.c_str(), &addr) == 1) {
        return ntohl(addr.s_addr);
    }
    return 0;
}

bool ip_matches(IPv4Address addr, const std::string& pattern) {
    if (pattern == "any") return true;
    return addr == string_to_ip(pattern);
}

bool port_matches(uint16_t port, const std::string& pattern) {
    if (pattern == "any") return true;
    return port == static_cast<uint16_t>(std::stoi(pattern));
}

} // namespace sf
