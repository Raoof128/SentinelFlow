#include "sentinelflow/utils/types.hpp"

#include <iomanip>
#include <sstream>

namespace sf {

std::string ip_to_string(IPv4Address addr) {
    return std::to_string((addr >> 24) & 0xFF) + "." + std::to_string((addr >> 16) & 0xFF) + "." +
           std::to_string((addr >> 8) & 0xFF) + "." + std::to_string(addr & 0xFF);
}

std::string mac_to_string(const MacAddress& addr) {
    std::ostringstream oss;
    for (size_t i = 0; i < 6; ++i) {
        if (i > 0)
            oss << ":";
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(addr[i]);
    }
    return oss.str();
}

}  // namespace sf
