#pragma once
#include <memory>
#include <string>
#include <vector>

#include "sentinelflow/alert/alert.hpp"
#include "sentinelflow/detection/dns_tunnel_detector.hpp"
#include "sentinelflow/detection/port_scan_detector.hpp"
#include "sentinelflow/detection/rule.hpp"
#include "sentinelflow/detection/rule_parser.hpp"
#include "sentinelflow/detection/signature_matcher.hpp"
#include "sentinelflow/detection/syn_flood_detector.hpp"
#include "sentinelflow/parser/packet.hpp"

namespace sf {

class DetectionEngine {
public:
    DetectionEngine();

    /// Load rules from a file and apply them (see apply_rules). Malformed lines are reported on
    /// stderr and counted in the returned stats; warnings from apply_rules are printed too.
    RuleLoadStats load_rules(const std::string& rules_file);

    /// Install `rules` and configure the stateful detectors from them:
    ///  - a `tcp` rule with `flags:S` and `threshold:count,seconds` sets the SYN-flood threshold
    ///    and window;
    ///  - a rule with `dns_query_len:>N` sets the DNS-tunnel name length (and, if it also has a
    ///    `threshold`, the query volume and window);
    ///  - any value no rule sets keeps its built-in default.
    /// Detector state is reset. Returns one warning per rule that cannot take effect: a
    /// `threshold` rule no detector consumes (for example ICMP flood, which is not implemented),
    /// a second rule for a detector that is already configured, or a stateful rule whose address
    /// or port fields are not `any` (the stateful detectors do not filter on them).
    std::vector<std::string> apply_rules(const std::vector<Rule>& rules);

    std::vector<Alert> analyze(const ParsedPacket& pkt);

private:
    std::unique_ptr<SignatureMatcher> signature_matcher_;
    PortScanDetector port_scan_detector_;
    SynFloodDetector syn_flood_detector_;
    DnsTunnelDetector dns_tunnel_detector_;
};

}  // namespace sf
