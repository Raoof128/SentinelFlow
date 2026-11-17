#pragma once
#include <memory>
#include <vector>

#include "sentinelflow/alert/alert.hpp"
#include "sentinelflow/detection/dns_tunnel_detector.hpp"
#include "sentinelflow/detection/port_scan_detector.hpp"
#include "sentinelflow/detection/signature_matcher.hpp"
#include "sentinelflow/detection/syn_flood_detector.hpp"
#include "sentinelflow/parser/packet.hpp"

namespace sf {

class DetectionEngine {
public:
    DetectionEngine();

    void load_rules(const std::string& rules_file);
    std::vector<Alert> analyze(const ParsedPacket& pkt);

private:
    std::unique_ptr<SignatureMatcher> signature_matcher_;
    PortScanDetector port_scan_detector_;
    SynFloodDetector syn_flood_detector_;
    DnsTunnelDetector dns_tunnel_detector_;
};

}  // namespace sf
