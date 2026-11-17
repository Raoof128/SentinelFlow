#pragma once
#include <chrono>
#include <cstdint>
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

/// SID of the alert raised when the stateful detectors' tables are full and dropping records.
constexpr uint32_t kStatePressureSid = 5100;

/// At most one state-pressure alert per this long (measured in packet time).
constexpr std::chrono::seconds kStatePressureAlertWindow{60};

/// Records each detector has dropped because its table was full.
struct StateEvictions {
    uint64_t port_scan = 0;
    uint64_t syn_flood = 0;
    uint64_t dns_tunnel = 0;

    uint64_t total() const { return port_scan + syn_flood + dns_tunnel; }
};

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

    /// Alerts for `pkt`. When the stateful detectors have had to drop live records because their
    /// tables were full, one extra MEDIUM alert (SID 5100, "State table pressure") is added, at
    /// most once per kStatePressureAlertWindow: while it is firing, detection of slow or
    /// distributed activity is degraded, and the operator should know.
    std::vector<Alert> analyze(const ParsedPacket& pkt);

    /// Cumulative capacity evictions per detector since the last apply_rules().
    StateEvictions state_evictions() const;

private:
    void check_state_pressure(const ParsedPacket& pkt, std::vector<Alert>& alerts);

    std::unique_ptr<SignatureMatcher> signature_matcher_;
    PortScanDetector port_scan_detector_;
    SynFloodDetector syn_flood_detector_;
    DnsTunnelDetector dns_tunnel_detector_;

    uint64_t reported_evictions_ = 0;  // evictions already covered by a pressure alert
    bool pressure_alerted_ = false;
    std::chrono::system_clock::time_point pressure_clock_ =
        std::chrono::system_clock::time_point::min();
    std::chrono::system_clock::time_point last_pressure_alert_{};
};

}  // namespace sf
