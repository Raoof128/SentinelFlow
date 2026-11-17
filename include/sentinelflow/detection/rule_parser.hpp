#pragma once
#include <string>
#include <vector>

#include "sentinelflow/detection/rule.hpp"

namespace sf {

class RuleParser {
public:
    static std::vector<Rule> load_from_file(const std::string& filepath);
    static std::optional<Rule> parse_line(const std::string& line);
};

}  // namespace sf
