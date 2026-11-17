#include "sentinelflow/detection/signature_matcher.hpp"

#include <algorithm>
#include <string_view>

#include "sentinelflow/utils/ip_utils.hpp"

namespace sf {

SignatureMatcher::SignatureMatcher(const std::vector<Rule>& rules) : rules_(rules) {}

std::vector<Alert> SignatureMatcher::check(const ParsedPacket& pkt) const {
    std::vector<Alert> alerts;
    for (const auto& rule : rules_) {
        // Rules with a threshold or a DNS query length are not per-packet signatures. The
        // DetectionEngine hands their values to the SYN-flood and DNS-tunnel detectors (see
        // DetectionEngine::apply_rules), so the matcher leaves them alone.
        if (rule.threshold_count)
            continue;
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

    // Check IPs. A rule that names an address cannot match a packet that has no IPv4 header.
    if (rule.src_ip != "any" || rule.dst_ip != "any") {
        if (!pkt.ipv4)
            return false;
        if (!ip_matches(pkt.ipv4->src_ip, rule.src_ip))
            return false;
        if (!ip_matches(pkt.ipv4->dst_ip, rule.dst_ip))
            return false;
    }

    // Check ports. A rule that names a port needs a TCP or UDP header to read it from: ICMP
    // messages and non-first IP fragments have none and must not match.
    if (rule.src_port != "any" || rule.dst_port != "any") {
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
        } else {
            return false;
        }
    }

    // Check TCP flags, which only a TCP packet has
    if (rule.tcp_flags) {
        if (!pkt.tcp)
            return false;
        if ((pkt.tcp->flags & *rule.tcp_flags) != *rule.tcp_flags)
            return false;
    }

    // Check content match. A content rule cannot match a packet that carries no payload.
    if (rule.content) {
        if (!pkt.payload || pkt.payload_length == 0)
            return false;
        std::string_view payload(reinterpret_cast<const char*>(pkt.payload), pkt.payload_length);
        if (payload.find(*rule.content) == std::string_view::npos)
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
