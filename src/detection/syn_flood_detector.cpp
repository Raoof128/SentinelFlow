#include "sentinelflow/detection/syn_flood_detector.hpp"

#include <algorithm>

namespace sf {

SynFloodDetector::SynFloodDetector(uint32_t syn_threshold, uint32_t time_window_sec,
                                   std::size_t max_tracked_targets)
    : threshold_(std::max<uint32_t>(syn_threshold, 1)),
      window_(std::chrono::seconds(time_window_sec)), targets_(max_tracked_targets) {}

std::optional<Alert> SynFloodDetector::check(const ParsedPacket& pkt) {
    if (!pkt.ipv4 || !pkt.tcp)
        return std::nullopt;
    if (!(pkt.tcp->flags & TCP_SYN) || (pkt.tcp->flags & TCP_ACK))
        return std::nullopt;

    latest_ = std::max(latest_, pkt.timestamp);
    const TimePoint now = latest_;
    const TimePoint cutoff = now - window_;
    const auto dst = pkt.ipv4->dst_ip;

    targets_.evict_idle(cutoff);
    auto& record = targets_.touch(dst, now);

    auto& syns = record.syns;
    while (!syns.empty() && syns.front() < cutoff)
        syns.pop_front();
    syns.push_back(now);
    // Only the newest `threshold_` timestamps matter for "are there threshold SYNs in the
    // window", so a flood cannot grow this queue past the threshold.
    while (syns.size() > threshold_)
        syns.pop_front();

    if (syns.size() < threshold_)
        return std::nullopt;
    if (record.alerted && now - record.last_alert < window_)
        return std::nullopt;

    record.alerted = true;
    record.last_alert = now;

    Alert alert;
    alert.severity = AlertSeverity::CRITICAL;
    alert.timestamp = pkt.timestamp;
    alert.dst_ip = dst;
    alert.src_ip = pkt.ipv4->src_ip;
    alert.message = "SYN flood detected: " + std::to_string(syns.size()) + " SYN packets in " +
                    std::to_string(window_.count()) + "s";
    alert.sid = 5002;
    return alert;
}

}  // namespace sf
