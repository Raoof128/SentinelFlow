#include "sentinelflow/detection/port_scan_detector.hpp"

namespace sf {

PortScanDetector::PortScanDetector(uint32_t port_threshold, uint32_t time_window_sec)
    : port_threshold_(port_threshold), time_window_(std::chrono::seconds(time_window_sec)) {}

std::optional<Alert> PortScanDetector::check(const ParsedPacket& pkt) {
    if (!pkt.ipv4 || !pkt.tcp)
        return std::nullopt;
    if (!(pkt.tcp->flags & TCP_SYN) || (pkt.tcp->flags & TCP_ACK))
        return std::nullopt;

    auto now = pkt.timestamp;
    auto key = make_key(pkt.ipv4->src_ip, pkt.ipv4->dst_ip);

    auto& record = connections_[key];
    prune_old(record, now);
    record.ports.insert(pkt.tcp->dst_port);
    record.timestamps.push_back(now);

    if (record.ports.size() >= port_threshold_) {
        Alert alert;
        alert.severity = AlertSeverity::HIGH;
        alert.timestamp = now;
        alert.src_ip = pkt.ipv4->src_ip;
        alert.dst_ip = pkt.ipv4->dst_ip;
        alert.message = "Port scan detected: " + std::to_string(record.ports.size()) +
                        " unique ports probed in " + std::to_string(time_window_.count()) + "s";
        alert.sid = 5001;

        record.ports.clear();
        record.timestamps.clear();
        return alert;
    }

    return std::nullopt;
}

uint64_t PortScanDetector::make_key(IPv4Address src, IPv4Address dst) {
    return (static_cast<uint64_t>(src) << 32) | dst;
}

void PortScanDetector::prune_old(ConnectionRecord& record,
                                 std::chrono::system_clock::time_point now) {
    auto cutoff = now - time_window_;
    while (!record.timestamps.empty() && record.timestamps.front() < cutoff) {
        record.timestamps.erase(record.timestamps.begin());
    }
    if (record.timestamps.empty())
        record.ports.clear();
}

}  // namespace sf
