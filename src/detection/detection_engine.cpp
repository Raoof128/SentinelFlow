#include "sentinelflow/detection/detection_engine.hpp"

#include "sentinelflow/detection/rule_parser.hpp"

namespace sf {

DetectionEngine::DetectionEngine()
    : port_scan_detector_(15, 60), syn_flood_detector_(100, 10), dns_tunnel_detector_(50, 20, 60) {}

void DetectionEngine::load_rules(const std::string& rules_file) {
    auto rules = RuleParser::load_from_file(rules_file);
    signature_matcher_ = std::make_unique<SignatureMatcher>(rules);
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
