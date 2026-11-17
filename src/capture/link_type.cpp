#include "sentinelflow/capture/link_type.hpp"

#include <iostream>

namespace sf {

bool require_ethernet_link(pcap_t* handle, const std::string& source) {
    const int link_type = pcap_datalink(handle);
    if (link_type == DLT_EN10MB)
        return true;

    const char* name = pcap_datalink_val_to_name(link_type);
    const char* description = pcap_datalink_val_to_description(link_type);
    std::cerr << source << ": unsupported link type " << (name ? name : "unknown") << " ("
              << link_type << (description ? std::string(", ") + description : std::string())
              << "). SentinelFlow reads Ethernet (DLT_EN10MB) captures only." << std::endl;
    return false;
}

}  // namespace sf
