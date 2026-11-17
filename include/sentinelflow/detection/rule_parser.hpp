#pragma once
#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include "sentinelflow/detection/rule.hpp"

namespace sf {

/// What load_from_file did with the rule lines in a file.
struct RuleLoadStats {
    std::size_t loaded = 0;    // lines that became rules
    std::size_t rejected = 0;  // non-blank, non-comment lines that were malformed
};

class RuleParser {
public:
    /// Read rules from `filepath`. Every malformed line is skipped with a warning on stderr that
    /// names the file, line number and reason, and a summary is printed if any were rejected.
    /// `stats`, if given, receives the counts.
    static std::vector<Rule> load_from_file(const std::string& filepath,
                                            RuleLoadStats* stats = nullptr);

    /// Parse one rule line. Returns nullopt for a malformed line and, if `error` is given,
    /// stores the reason there.
    static std::optional<Rule> parse_line(const std::string& line, std::string* error = nullptr);
};

}  // namespace sf
