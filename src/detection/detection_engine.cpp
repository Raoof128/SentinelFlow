#include "sentinelflow/detection/detection_engine.hpp"

#include <iostream>

#include "sentinelflow/detection/rule_parser.hpp"

namespace sf {

namespace {

bool is_syn_flood_rule(const Rule& rule) {
    return rule.threshold_count && rule.threshold_seconds && rule.protocol == "tcp" &&
           rule.tcp_flags && *rule.tcp_flags == TCP_SYN;
}

// True if the rule restricts addresses or ports beyond what its detector already assumes
// (`implied_dst_port` is the destination port the detector inherently looks at, if any).
bool has_address_filter(const Rule& rule, const std::string& implied_dst_port = "any") {
    return rule.src_ip != "any" || rule.src_port != "any" || rule.dst_ip != "any" ||
           (rule.dst_port != "any" && rule.dst_port != implied_dst_port);
}

std::string describe(const Rule& rule) {
    return "sid " + std::to_string(rule.sid) + ": ";
}

}  // namespace

DetectionEngine::DetectionEngine()
    : port_scan_detector_(kDefaultPortScanPorts, kDefaultPortScanWindowSec),
      syn_flood_detector_(kDefaultSynFloodThreshold, kDefaultSynFloodWindowSec),
      dns_tunnel_detector_(kDefaultDnsQueryLength, kDefaultDnsVolume, kDefaultDnsWindowSec) {}

RuleLoadStats DetectionEngine::load_rules(const std::string& rules_file) {
    RuleLoadStats stats;
    auto rules = RuleParser::load_from_file(rules_file, &stats);
    for (const auto& warning : apply_rules(rules))
        std::cerr << "rules: " << warning << std::endl;
    return stats;
}

std::vector<std::string> DetectionEngine::apply_rules(const std::vector<Rule>& rules) {
    std::vector<std::string> warnings;

    uint32_t syn_threshold = kDefaultSynFloodThreshold;
    uint32_t syn_window = kDefaultSynFloodWindowSec;
    const Rule* syn_rule = nullptr;

    uint32_t dns_length = kDefaultDnsQueryLength;
    uint32_t dns_volume = kDefaultDnsVolume;
    uint32_t dns_window = kDefaultDnsWindowSec;
    const Rule* dns_rule = nullptr;

    for (const auto& rule : rules) {
        if (is_syn_flood_rule(rule)) {
            if (syn_rule) {
                warnings.push_back(describe(rule) + "ignored, the SYN flood detector is already " +
                                   "configured by sid " + std::to_string(syn_rule->sid));
                continue;
            }
            syn_rule = &rule;
            syn_threshold = *rule.threshold_count;
            syn_window = *rule.threshold_seconds;
            if (has_address_filter(rule))
                warnings.push_back(describe(rule) + "the SYN flood detector counts SYNs to every " +
                                   "destination; the rule's address and port fields are ignored");
        } else if (rule.dns_query_min_len) {
            if (dns_rule) {
                warnings.push_back(describe(rule) + "ignored, the DNS tunnel detector is already " +
                                   "configured by sid " + std::to_string(dns_rule->sid));
                continue;
            }
            dns_rule = &rule;
            dns_length = *rule.dns_query_min_len;
            if (rule.threshold_count && rule.threshold_seconds) {
                dns_volume = *rule.threshold_count;
                dns_window = *rule.threshold_seconds;
            }
            if (has_address_filter(rule, "53"))
                warnings.push_back(describe(rule) + "the DNS tunnel detector inspects all DNS " +
                                   "queries; the rule's address and port fields are ignored");
        } else if (rule.threshold_count) {
            warnings.push_back(describe(rule) +
                               "has no effect: threshold is only supported on a tcp rule with " +
                               "flags:S (SYN flood) or together with dns_query_len; " +
                               "this includes ICMP flood, which is not implemented");
        }
    }

    syn_flood_detector_ = SynFloodDetector(syn_threshold, syn_window);
    dns_tunnel_detector_ = DnsTunnelDetector(dns_length, dns_volume, dns_window);
    signature_matcher_ = std::make_unique<SignatureMatcher>(rules);
    return warnings;
}

std::vector<Alert> DetectionEngine::analyze(const ParsedPacket& pkt) {
    std::vector<Alert> alerts;

    // Signature-based detection
    if (signature_matcher_) {
        auto sig_alerts = signature_matcher_->check(pkt);
        alerts.insert(alerts.end(), sig_alerts.begin(), sig_alerts.end());
    }

    // Stateful detection
    if (auto alert = port_scan_detector_.check(pkt))
        alerts.push_back(std::move(*alert));

    if (auto alert = syn_flood_detector_.check(pkt))
        alerts.push_back(std::move(*alert));

    if (auto alert = dns_tunnel_detector_.check(pkt))
        alerts.push_back(std::move(*alert));

    return alerts;
}

}  // namespace sf
