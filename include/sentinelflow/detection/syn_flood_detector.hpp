#pragma once
#include <deque>
#include <optional>
#include <unordered_map>

#include "sentinelflow/alert/alert.hpp"
#include "sentinelflow/parser/packet.hpp"

namespace sf {

class SynFloodDetector {
public:
    SynFloodDetector(uint32_t syn_threshold = 100, uint32_t time_window_sec = 10);

    std::optional<Alert> check(const ParsedPacket& pkt);

private:
    uint32_t threshold_;
    std::chrono::seconds window_;
    std::unordered_map<IPv4Address, std::deque<std::chrono::system_clock::time_point>> target_syns_;
};

}  // namespace sf
