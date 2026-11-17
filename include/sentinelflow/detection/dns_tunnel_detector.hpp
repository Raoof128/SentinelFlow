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
/// than `query_len_threshold` characters within the time window.
///
/// Whether a message is a response is decided by the transport, not by the DNS QR bit, which the
/// sender controls: a message from port 53 to another port is a server's reply and is ignored;
/// a message sent to port 53 is analysed whatever its QR bit says. (A client that sets QR=1 on
/// its queries must not be able to opt out of detection.) Tracked sources are bounded: see
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

    /// Sources dropped because the table was full (see SourceTable).
    uint64_t capacity_evictions() const { return sources_.capacity_evictions(); }

private:
    using TimePoint = std::chrono::system_clock::time_point;

    struct SourceRecord {
        std::deque<TimePoint> queries;  // long queries inside the window; < volume_threshold_

        std::size_t progress() const { return queries.size(); }
    };

    uint32_t query_len_threshold_;
    uint32_t volume_threshold_;
    std::chrono::seconds window_;
    TimePoint latest_ = TimePoint::min();  // newest packet time seen; keeps time monotonic
    SourceTable<IPv4Address, SourceRecord> sources_;
};

}  // namespace sf
