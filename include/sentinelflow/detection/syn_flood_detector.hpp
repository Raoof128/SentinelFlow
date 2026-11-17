#pragma once
#include <chrono>
#include <deque>
#include <optional>

#include "sentinelflow/alert/alert.hpp"
#include "sentinelflow/detection/source_table.hpp"
#include "sentinelflow/parser/packet.hpp"

namespace sf {

constexpr uint32_t kDefaultSynFloodThreshold = 100;
constexpr uint32_t kDefaultSynFloodWindowSec = 10;

/// Alerts (SID 5002) when a destination receives `syn_threshold` SYNs within the time window,
/// from any mix of sources. While a flood continues it alerts once per time window per
/// destination, not once per threshold-th packet. Tracked destinations are bounded: see
/// kDefaultMaxTrackedSources.
class SynFloodDetector {
public:
    SynFloodDetector(uint32_t syn_threshold = kDefaultSynFloodThreshold,
                     uint32_t time_window_sec = kDefaultSynFloodWindowSec,
                     std::size_t max_tracked_targets = kDefaultMaxTrackedSources);

    std::optional<Alert> check(const ParsedPacket& pkt);

    /// Number of destinations currently tracked.
    std::size_t tracked_targets() const { return targets_.size(); }

private:
    using TimePoint = std::chrono::system_clock::time_point;

    struct TargetRecord {
        std::deque<TimePoint> syns;  // newest syn_threshold SYNs inside the window
        bool alerted = false;
        TimePoint last_alert{};
    };

    uint32_t threshold_;
    std::chrono::seconds window_;
    TimePoint latest_ = TimePoint::min();  // newest packet time seen; keeps time monotonic
    SourceTable<IPv4Address, TargetRecord> targets_;
};

}  // namespace sf
