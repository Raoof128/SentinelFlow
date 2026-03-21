#include "sentinelflow/detection/rule_parser.hpp"
#include <fstream>
#include <sstream>
#include <iostream>
#include <regex>

namespace sf {

std::vector<Rule> RuleParser::load_from_file(const std::string& filepath) {
    std::vector<Rule> rules;
    std::ifstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "Failed to open rules file: " << filepath << std::endl;
        return rules;
    }

    std::string line;
    while (std::getline(file, line)) {
        // Skip comments and empty lines
        if (line.empty() || line[0] == '#') continue;

        auto rule = parse_line(line);
        if (rule) {
            rules.push_back(std::move(*rule));
        }
    }
    return rules;
}

std::optional<Rule> RuleParser::parse_line(const std::string& line) {
    // Format: action protocol src_ip src_port -> dst_ip dst_port (options)
    std::istringstream iss(line);
    Rule rule{};

    std::string arrow;
    if (!(iss >> rule.action >> rule.protocol >> rule.src_ip >> rule.src_port
              >> arrow >> rule.dst_ip >> rule.dst_port)) {
        return std::nullopt;
    }

    if (arrow != "->") return std::nullopt;

    // Parse options in parentheses
    std::string rest;
    std::getline(iss, rest);

    auto opt_start = rest.find('(');
    auto opt_end = rest.rfind(')');
    if (opt_start == std::string::npos || opt_end == std::string::npos)
        return std::nullopt;

    std::string options = rest.substr(opt_start + 1, opt_end - opt_start - 1);

    // Parse individual options separated by ';'
    std::istringstream opt_stream(options);
    std::string option;
    while (std::getline(opt_stream, option, ';')) {
        // Trim whitespace
        auto start = option.find_first_not_of(" \t");
        if (start == std::string::npos) continue;
        option = option.substr(start);

        if (option.substr(0, 4) == "msg:") {
            auto q1 = option.find('"');
            auto q2 = option.rfind('"');
            if (q1 != std::string::npos && q2 != q1) {
                rule.message = option.substr(q1 + 1, q2 - q1 - 1);
            }
        } else if (option.substr(0, 4) == "sid:") {
            rule.sid = std::stoul(option.substr(4));
        } else if (option.substr(0, 6) == "flags:") {
            std::string flags_str = option.substr(6);
            uint8_t flags = 0;
            for (char c : flags_str) {
                switch (c) {
                    case 'S': flags |= 0x02; break; // SYN
                    case 'A': flags |= 0x10; break; // ACK
                    case 'F': flags |= 0x01; break; // FIN
                    case 'R': flags |= 0x04; break; // RST
                    case 'P': flags |= 0x08; break; // PSH
                    case 'U': flags |= 0x20; break; // URG
                }
            }
            rule.tcp_flags = flags;
        } else if (option.substr(0, 10) == "threshold:") {
            auto vals = option.substr(10);
            auto comma = vals.find(',');
            if (comma != std::string::npos) {
                rule.threshold_count = std::stoul(vals.substr(0, comma));
                rule.threshold_seconds = std::stoul(vals.substr(comma + 1));
            }
        } else if (option.substr(0, 15) == "dns_query_len:>") {
            rule.dns_query_min_len = std::stoul(option.substr(15));
        } else if (option.substr(0, 8) == "content:") {
            auto q1 = option.find('"');
            auto q2 = option.rfind('"');
            if (q1 != std::string::npos && q2 != q1) {
                rule.content = option.substr(q1 + 1, q2 - q1 - 1);
            }
        }
    }

    return rule;
}

} // namespace sf
