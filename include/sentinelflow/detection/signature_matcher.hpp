#pragma once
#include <optional>
#include <vector>

#include "sentinelflow/alert/alert.hpp"
#include "sentinelflow/detection/rule.hpp"
#include "sentinelflow/parser/packet.hpp"

namespace sf {

class SignatureMatcher {
public:
    explicit SignatureMatcher(const std::vector<Rule>& rules);

    std::vector<Alert> check(const ParsedPacket& pkt) const;

private:
    bool matches_rule(const ParsedPacket& pkt, const Rule& rule) const;
    std::string protocol_string(const ParsedPacket& pkt) const;

    std::vector<Rule> rules_;
};

}  // namespace sf
