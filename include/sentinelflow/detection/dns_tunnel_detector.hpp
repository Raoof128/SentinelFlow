#pragma once
#include <deque>
#include <optional>
#include <unordered_map>

#include "sentinelflow/alert/alert.hpp"
#include "sentinelflow/parser/packet.hpp"

namespace sf {

class DnsTunnelDetector {
public:
    DnsTunnelDetector(uint32_t query_len_threshold = 50, uint32_t volume_threshold = 20,
                      uint32_t time_window_sec = 60);

    std::optional<Alert> check(const ParsedPacket& pkt);

private:
    uint32_t query_len_threshold_;
    uint32_t volume_threshold_;
    std::chrono::seconds window_;
    std::unordered_map<IPv4Address, std::deque<std::chrono::system_clock::time_point>>
        suspicious_queries_;
};

}  // namespace sf
