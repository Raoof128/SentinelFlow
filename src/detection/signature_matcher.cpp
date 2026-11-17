#include "sentinelflow/detection/signature_matcher.hpp"

#include <algorithm>

#include "sentinelflow/utils/ip_utils.hpp"

namespace sf {

SignatureMatcher::SignatureMatcher(const std::vector<Rule>& rules) : rules_(rules) {}

std::vector<Alert> SignatureMatcher::check(const ParsedPacket& pkt) const {
    std::vector<Alert> alerts;
    for (const auto& rule : rules_) {
        // Skip rules with thresholds (handled by stateful detectors)
        if (rule.threshold_count)
            continue;
        // Skip DNS-specific rules (handled by DnsTunnelDetector)
        if (rule.dns_query_min_len)
            continue;

        if (matches_rule(pkt, rule)) {
            Alert alert;
            alert.sid = rule.sid;
            alert.severity = AlertSeverity::MEDIUM;
            alert.timestamp = pkt.timestamp;
            alert.message = rule.message;
            if (pkt.ipv4) {
                alert.src_ip = pkt.ipv4->src_ip;
                alert.dst_ip = pkt.ipv4->dst_ip;
            }
            if (pkt.tcp) {
                alert.src_port = pkt.tcp->src_port;
                alert.dst_port = pkt.tcp->dst_port;
            } else if (pkt.udp) {
                alert.src_port = pkt.udp->src_port;
                alert.dst_port = pkt.udp->dst_port;
            }
            alerts.push_back(std::move(alert));
        }
    }
    return alerts;
}

bool SignatureMatcher::matches_rule(const ParsedPacket& pkt, const Rule& rule) const {
    // Check protocol
    std::string pkt_proto = protocol_string(pkt);
    if (rule.protocol != "any" && rule.protocol != pkt_proto)
        return false;

    // Check IPs
    if (pkt.ipv4) {
        if (!ip_matches(pkt.ipv4->src_ip, rule.src_ip))
            return false;
        if (!ip_matches(pkt.ipv4->dst_ip, rule.dst_ip))
            return false;
    }

    // Check ports
    if (pkt.tcp) {
        if (!port_matches(pkt.tcp->src_port, rule.src_port))
            return false;
        if (!port_matches(pkt.tcp->dst_port, rule.dst_port))
            return false;
    } else if (pkt.udp) {
        if (!port_matches(pkt.udp->src_port, rule.src_port))
            return false;
        if (!port_matches(pkt.udp->dst_port, rule.dst_port))
            return false;
    }

    // Check TCP flags
    if (rule.tcp_flags && pkt.tcp) {
        if ((pkt.tcp->flags & *rule.tcp_flags) != *rule.tcp_flags)
            return false;
    }

    // Check content match
    if (rule.content && pkt.payload && pkt.payload_length > 0) {
        std::string payload_str(reinterpret_cast<const char*>(pkt.payload), pkt.payload_length);
        if (payload_str.find(*rule.content) == std::string::npos)
            return false;
    }

    return true;
}

std::string SignatureMatcher::protocol_string(const ParsedPacket& pkt) const {
    if (pkt.tcp)
        return "tcp";
    if (pkt.udp)
        return "udp";
    if (pkt.icmp)
        return "icmp";
    return "unknown";
}

}  // namespace sf
