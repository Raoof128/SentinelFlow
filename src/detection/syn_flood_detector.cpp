#include "sentinelflow/detection/syn_flood_detector.hpp"

namespace sf {

SynFloodDetector::SynFloodDetector(uint32_t syn_threshold, uint32_t time_window_sec)
    : threshold_(syn_threshold),
      window_(std::chrono::seconds(time_window_sec)) {}

std::optional<Alert> SynFloodDetector::check(const ParsedPacket& pkt) {
    if (!pkt.ipv4 || !pkt.tcp) return std::nullopt;
    if (!(pkt.tcp->flags & TCP_SYN) || (pkt.tcp->flags & TCP_ACK))
        return std::nullopt;

    auto now = pkt.timestamp;
    auto dst = pkt.ipv4->dst_ip;

    auto& syn_times = target_syns_[dst];
    syn_times.push_back(now);

    auto cutoff = now - window_;
    while (!syn_times.empty() && syn_times.front() < cutoff)
        syn_times.pop_front();

    if (syn_times.size() >= threshold_) {
        Alert alert;
        alert.severity  = AlertSeverity::CRITICAL;
        alert.timestamp = now;
        alert.dst_ip    = dst;
        alert.src_ip    = pkt.ipv4->src_ip;
        alert.message   = "SYN flood detected: " +
                          std::to_string(syn_times.size()) +
                          " SYN packets in " +
                          std::to_string(window_.count()) + "s";
        alert.sid       = 5002;

        syn_times.clear();
        return alert;
    }

    return std::nullopt;
}

} // namespace sf
