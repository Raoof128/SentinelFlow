#pragma once
#include <chrono>
#include <deque>
#include <optional>

#include "sentinelflow/alert/alert.hpp"
#include "sentinelflow/detection/source_table.hpp"
#include "sentinelflow/parser/packet.hpp"

namespace sf {

constexpr uint32_t kDefaultDnsQueryLength = 50;
constexpr uint32_t kDefaultDnsVolume = 20;
constexpr uint32_t kDefaultDnsWindowSec = 60;

/// Alerts (SID 5003) when one source sends `volume_threshold` DNS queries whose name is longer
/// than `query_len_threshold` characters within the time window. DNS responses are ignored: a
/// long name in a response is the server echoing a query. Tracked sources are bounded: see
/// kDefaultMaxTrackedSources.
class DnsTunnelDetector {
public:
    DnsTunnelDetector(uint32_t query_len_threshold = kDefaultDnsQueryLength,
                      uint32_t volume_threshold = kDefaultDnsVolume,
                      uint32_t time_window_sec = kDefaultDnsWindowSec,
                      std::size_t max_tracked_sources = kDefaultMaxTrackedSources);

    std::optional<Alert> check(const ParsedPacket& pkt);

    /// Number of sources currently tracked.
    std::size_t tracked_sources() const { return sources_.size(); }

private:
    using TimePoint = std::chrono::system_clock::time_point;

    struct SourceRecord {
        std::deque<TimePoint> queries;  // long queries inside the window; < volume_threshold_
    };

    uint32_t query_len_threshold_;
    uint32_t volume_threshold_;
    std::chrono::seconds window_;
    TimePoint latest_ = TimePoint::min();  // newest packet time seen; keeps time monotonic
    SourceTable<IPv4Address, SourceRecord> sources_;
};

}  // namespace sf
