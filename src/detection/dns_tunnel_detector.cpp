#include "sentinelflow/detection/dns_tunnel_detector.hpp"

#include <algorithm>

namespace sf {

DnsTunnelDetector::DnsTunnelDetector(uint32_t query_len_threshold, uint32_t volume_threshold,
                                     uint32_t time_window_sec, std::size_t max_tracked_sources)
    : query_len_threshold_(query_len_threshold),
      volume_threshold_(std::max<uint32_t>(volume_threshold, 1)),
      window_(std::chrono::seconds(time_window_sec)), sources_(max_tracked_sources) {}

std::optional<Alert> DnsTunnelDetector::check(const ParsedPacket& pkt) {
    if (!pkt.ipv4 || !pkt.dns)
        return std::nullopt;
    if (pkt.dns->is_response)
        return std::nullopt;

    // Check if query name is suspiciously long
    if (pkt.dns->query_name.length() <= query_len_threshold_)
        return std::nullopt;

    latest_ = std::max(latest_, pkt.timestamp);
    const TimePoint now = latest_;
    const TimePoint cutoff = now - window_;
    const auto src = pkt.ipv4->src_ip;

    sources_.evict_idle(cutoff);
    auto& queries = sources_.touch(src, now).queries;
    while (!queries.empty() && queries.front() < cutoff)
        queries.pop_front();
    queries.push_back(now);

    if (queries.size() >= volume_threshold_) {
        Alert alert;
        alert.severity = AlertSeverity::HIGH;
        alert.timestamp = pkt.timestamp;
        alert.src_ip = src;
        alert.dst_ip = pkt.ipv4->dst_ip;
        alert.message = "Possible DNS tunnelling: " + std::to_string(queries.size()) +
                        " long DNS queries in " + std::to_string(window_.count()) +
                        "s from same source";
        alert.sid = 5003;

        queries.clear();
        return alert;
    }

    return std::nullopt;
}

}  // namespace sf
