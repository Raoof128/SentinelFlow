#pragma once
#include <chrono>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "sentinelflow/alert/alert.hpp"
#include "sentinelflow/parser/packet.hpp"

namespace sf {

class PortScanDetector {
public:
    PortScanDetector(uint32_t port_threshold = 15, uint32_t time_window_sec = 60);

    std::optional<Alert> check(const ParsedPacket& pkt);

private:
    struct ConnectionRecord {
        std::unordered_set<uint16_t> ports;
        std::vector<std::chrono::system_clock::time_point> timestamps;
    };

    uint64_t make_key(IPv4Address src, IPv4Address dst);
    void prune_old(ConnectionRecord& record, std::chrono::system_clock::time_point now);

    uint32_t port_threshold_;
    std::chrono::seconds time_window_;
    std::unordered_map<uint64_t, ConnectionRecord> connections_;
};

}  // namespace sf
