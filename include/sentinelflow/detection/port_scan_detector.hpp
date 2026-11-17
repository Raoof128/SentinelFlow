#pragma once
#include <chrono>
#include <list>
#include <optional>
#include <unordered_map>
#include <utility>

#include "sentinelflow/alert/alert.hpp"
#include "sentinelflow/detection/source_table.hpp"
#include "sentinelflow/parser/packet.hpp"

namespace sf {

constexpr uint32_t kDefaultPortScanPorts = 15;
constexpr uint32_t kDefaultPortScanWindowSec = 60;

/// Alerts (SID 5001) when one source probes `port_threshold` distinct TCP ports on one
/// destination within the time window. Only ports whose most recent SYN is inside the window
/// count. Tracked state is bounded: see kDefaultMaxTrackedSources.
class PortScanDetector {
public:
    PortScanDetector(uint32_t port_threshold = kDefaultPortScanPorts,
                     uint32_t time_window_sec = kDefaultPortScanWindowSec,
                     std::size_t max_tracked_pairs = kDefaultMaxTrackedSources);

    std::optional<Alert> check(const ParsedPacket& pkt);

    /// Number of source/destination pairs currently tracked.
    std::size_t tracked_pairs() const { return pairs_.size(); }

    /// Pairs dropped because the table was full (see SourceTable).
    uint64_t capacity_evictions() const { return pairs_.capacity_evictions(); }

private:
    using TimePoint = std::chrono::system_clock::time_point;

    // Ports probed by one source against one destination, oldest SYN first. A repeated SYN moves
    // its port to the back, so `ports` stays ordered by time and expiry only touches the front.
    // A record never holds more than port_threshold_ ports: reaching it raises the alert and
    // clears the record.
    struct PairRecord {
        std::list<std::pair<uint16_t, TimePoint>> ports;
        std::unordered_map<uint16_t, std::list<std::pair<uint16_t, TimePoint>>::iterator> index;

        std::size_t progress() const { return index.size(); }
    };

    static uint64_t make_key(IPv4Address src, IPv4Address dst);
    static void drop_ports_before(PairRecord& record, TimePoint cutoff);

    uint32_t port_threshold_;
    std::chrono::seconds time_window_;
    TimePoint latest_ = TimePoint::min();  // newest packet time seen; keeps time monotonic
    SourceTable<uint64_t, PairRecord> pairs_;
};

}  // namespace sf
