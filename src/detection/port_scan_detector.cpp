#include "sentinelflow/detection/port_scan_detector.hpp"

#include <algorithm>
#include <iterator>

namespace sf {

PortScanDetector::PortScanDetector(uint32_t port_threshold, uint32_t time_window_sec,
                                   std::size_t max_tracked_pairs)
    : port_threshold_(std::max<uint32_t>(port_threshold, 1)),
      time_window_(std::chrono::seconds(time_window_sec)), pairs_(max_tracked_pairs) {}

std::optional<Alert> PortScanDetector::check(const ParsedPacket& pkt) {
    if (!pkt.ipv4 || !pkt.tcp)
        return std::nullopt;
    if (!(pkt.tcp->flags & TCP_SYN) || (pkt.tcp->flags & TCP_ACK))
        return std::nullopt;

    latest_ = std::max(latest_, pkt.timestamp);
    const TimePoint now = latest_;
    const TimePoint cutoff = now - time_window_;

    pairs_.evict_idle(cutoff);
    auto& record = pairs_.touch(make_key(pkt.ipv4->src_ip, pkt.ipv4->dst_ip), now);
    drop_ports_before(record, cutoff);

    const uint16_t port = pkt.tcp->dst_port;
    auto seen = record.index.find(port);
    if (seen != record.index.end()) {
        seen->second->second = now;
        record.ports.splice(record.ports.end(), record.ports, seen->second);
    } else {
        record.ports.emplace_back(port, now);
        record.index.emplace(port, std::prev(record.ports.end()));
    }

    if (record.index.size() >= port_threshold_) {
        Alert alert;
        alert.severity = AlertSeverity::HIGH;
        alert.timestamp = pkt.timestamp;
        alert.src_ip = pkt.ipv4->src_ip;
        alert.dst_ip = pkt.ipv4->dst_ip;
        alert.message = "Port scan detected: " + std::to_string(record.index.size()) +
                        " unique ports probed in " + std::to_string(time_window_.count()) + "s";
        alert.sid = 5001;

        record.ports.clear();
        record.index.clear();
        return alert;
    }

    return std::nullopt;
}

uint64_t PortScanDetector::make_key(IPv4Address src, IPv4Address dst) {
    return (static_cast<uint64_t>(src) << 32) | dst;
}

void PortScanDetector::drop_ports_before(PairRecord& record, TimePoint cutoff) {
    while (!record.ports.empty() && record.ports.front().second < cutoff) {
        record.index.erase(record.ports.front().first);
        record.ports.pop_front();
    }
}

}  // namespace sf
