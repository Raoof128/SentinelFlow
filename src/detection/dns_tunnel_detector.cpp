#include "sentinelflow/detection/dns_tunnel_detector.hpp"

namespace sf {

DnsTunnelDetector::DnsTunnelDetector(uint32_t query_len_threshold, uint32_t volume_threshold,
                                     uint32_t time_window_sec)
    : query_len_threshold_(query_len_threshold), volume_threshold_(volume_threshold),
      window_(std::chrono::seconds(time_window_sec)) {}

std::optional<Alert> DnsTunnelDetector::check(const ParsedPacket& pkt) {
    if (!pkt.ipv4 || !pkt.dns)
        return std::nullopt;

    // Check if query name is suspiciously long
    if (pkt.dns->query_name.length() <= query_len_threshold_)
        return std::nullopt;

    auto now = pkt.timestamp;
    auto src = pkt.ipv4->src_ip;

    auto& queries = suspicious_queries_[src];
    queries.push_back(now);

    // Prune old entries
    auto cutoff = now - window_;
    while (!queries.empty() && queries.front() < cutoff)
        queries.pop_front();

    if (queries.size() >= volume_threshold_) {
        Alert alert;
        alert.severity = AlertSeverity::HIGH;
        alert.timestamp = now;
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
