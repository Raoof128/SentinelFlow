#include "sentinelflow/detection/rule_parser.hpp"

#include <fstream>
#include <iostream>
#include <sstream>

#include "sentinelflow/utils/ip_utils.hpp"

namespace sf {

namespace {

std::nullopt_t reject(std::string* error, std::string message) {
    if (error)
        *error = std::move(message);
    return std::nullopt;
}

std::string trim(const std::string& s) {
    const auto first = s.find_first_not_of(" \t\r\n");
    if (first == std::string::npos)
        return "";
    const auto last = s.find_last_not_of(" \t\r\n");
    return s.substr(first, last - first + 1);
}

// Parse an unsigned decimal that fits in uint32_t. Rejects signs, spaces and trailing text,
// which std::stoul would accept (it wraps "-1" around to a huge value).
std::optional<uint32_t> parse_uint32(const std::string& text) {
    if (text.empty() || text.size() > 10)
        return std::nullopt;
    uint64_t value = 0;
    for (char c : text) {
        if (c < '0' || c > '9')
            return std::nullopt;
        value = value * 10 + static_cast<uint64_t>(c - '0');
    }
    if (value > 0xFFFFFFFFull)
        return std::nullopt;
    return static_cast<uint32_t>(value);
}

// Split the text between the parentheses on ';', ignoring semicolons inside double quotes.
std::vector<std::string> split_options(const std::string& options) {
    std::vector<std::string> parts;
    std::string current;
    bool in_quotes = false;
    for (char c : options) {
        if (c == '"')
            in_quotes = !in_quotes;
        if (c == ';' && !in_quotes) {
            parts.push_back(current);
            current.clear();
        } else {
            current += c;
        }
    }
    parts.push_back(current);
    return parts;
}

// "text" -> text. Nullopt unless the value is wrapped in double quotes.
std::optional<std::string> unquote(const std::string& value) {
    if (value.size() < 2 || value.front() != '"' || value.back() != '"')
        return std::nullopt;
    return value.substr(1, value.size() - 2);
}

bool is_known_protocol(const std::string& protocol) {
    return protocol == "tcp" || protocol == "udp" || protocol == "icmp" || protocol == "any";
}

}  // namespace

std::vector<Rule> RuleParser::load_from_file(const std::string& filepath, RuleLoadStats* stats) {
    std::vector<Rule> rules;
    RuleLoadStats local;
    std::ifstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "Failed to open rules file: " << filepath << std::endl;
        if (stats)
            *stats = local;
        return rules;
    }

    std::string line;
    std::size_t line_number = 0;
    std::size_t rule_lines = 0;
    while (std::getline(file, line)) {
        ++line_number;
        const std::string text = trim(line);
        // Skip comments and empty lines
        if (text.empty() || text[0] == '#')
            continue;

        ++rule_lines;
        std::string error;
        auto rule = parse_line(text, &error);
        if (rule) {
            rules.push_back(std::move(*rule));
            ++local.loaded;
        } else {
            ++local.rejected;
            std::cerr << "rules: " << filepath << ":" << line_number << ": rejected: " << error
                      << std::endl;
        }
    }
    if (local.rejected > 0) {
        std::cerr << "rules: " << local.rejected << " of " << rule_lines << " rule lines in "
                  << filepath << " were rejected and not loaded" << std::endl;
    }
    if (stats)
        *stats = local;
    return rules;
}

std::optional<Rule> RuleParser::parse_line(const std::string& line, std::string* error) {
    // Format: action protocol src_ip src_port -> dst_ip dst_port (options)
    std::istringstream iss(line);
    Rule rule{};

    std::string arrow;
    if (!(iss >> rule.action >> rule.protocol >> rule.src_ip >> rule.src_port >> arrow >>
          rule.dst_ip >> rule.dst_port)) {
        return reject(error, "expected: action protocol src_ip src_port -> dst_ip dst_port (...)");
    }

    if (arrow != "->")
        return reject(error, "expected '->' after the source port, found '" + arrow + "'");
    if (!is_known_protocol(rule.protocol))
        return reject(error, "unknown protocol '" + rule.protocol + "' (use tcp, udp, icmp, any)");
    for (const std::string* ip : {&rule.src_ip, &rule.dst_ip}) {
        if (!is_valid_ip_pattern(*ip))
            return reject(error,
                          "invalid address '" + *ip + "' (use any, a.b.c.d or a.b.c.d/prefix)");
    }
    for (const std::string* port : {&rule.src_port, &rule.dst_port}) {
        if (!is_valid_port_pattern(*port))
            return reject(error, "invalid port '" + *port + "' (use any or a number 0-65535)");
    }

    // Parse options in parentheses
    std::string rest;
    std::getline(iss, rest);

    auto opt_start = rest.find('(');
    auto opt_end = rest.rfind(')');
    if (opt_start == std::string::npos || opt_end == std::string::npos || opt_end < opt_start)
        return reject(error, "missing option list in parentheses");
    if (!trim(rest.substr(0, opt_start)).empty())
        return reject(error, "unexpected text before the option list");
    const std::string tail = trim(rest.substr(opt_end + 1));
    if (!tail.empty() && tail[0] != '#')
        return reject(error, "unexpected text after the option list");

    std::string options = rest.substr(opt_start + 1, opt_end - opt_start - 1);

    // Parse individual options separated by ';'
    for (const std::string& raw_option : split_options(options)) {
        const std::string option = trim(raw_option);
        if (option.empty())
            continue;

        const auto colon = option.find(':');
        const std::string name = trim(option.substr(0, colon));
        const std::string value =
            (colon == std::string::npos) ? "" : trim(option.substr(colon + 1));

        if (name == "msg") {
            auto text = unquote(value);
            if (!text)
                return reject(error, "msg must be a double-quoted string");
            rule.message = *text;
        } else if (name == "sid") {
            auto sid = parse_uint32(value);
            if (!sid)
                return reject(error,
                              "invalid sid '" + value + "' (must be a non-negative integer)");
            rule.sid = *sid;
        } else if (name == "flags") {
            if (value.empty())
                return reject(error, "flags needs at least one of S A F R P U");
            uint8_t flags = 0;
            for (char c : value) {
                switch (c) {
                    case 'S':
                        flags |= 0x02;
                        break;  // SYN
                    case 'A':
                        flags |= 0x10;
                        break;  // ACK
                    case 'F':
                        flags |= 0x01;
                        break;  // FIN
                    case 'R':
                        flags |= 0x04;
                        break;  // RST
                    case 'P':
                        flags |= 0x08;
                        break;  // PSH
                    case 'U':
                        flags |= 0x20;
                        break;  // URG
                    default:
                        return reject(error, std::string("unknown TCP flag '") + c +
                                                 "' (use S A F R P U)");
                }
            }
            rule.tcp_flags = flags;
        } else if (name == "threshold") {
            const auto comma = value.find(',');
            std::optional<uint32_t> count, seconds;
            if (comma != std::string::npos) {
                count = parse_uint32(trim(value.substr(0, comma)));
                seconds = parse_uint32(trim(value.substr(comma + 1)));
            }
            if (!count || !seconds || *count == 0 || *seconds == 0)
                return reject(error, "invalid threshold '" + value +
                                         "' (use count,seconds with both at least 1)");
            rule.threshold_count = *count;
            rule.threshold_seconds = *seconds;
        } else if (name == "dns_query_len") {
            std::optional<uint32_t> min_len;
            if (!value.empty() && value[0] == '>')
                min_len = parse_uint32(trim(value.substr(1)));
            if (!min_len)
                return reject(error, "invalid dns_query_len '" + value + "' (use >N)");
            rule.dns_query_min_len = *min_len;
        } else if (name == "content") {
            auto text = unquote(value);
            if (!text)
                return reject(error, "content must be a double-quoted string");
            rule.content = *text;
        } else {
            return reject(error, "unsupported option '" + name + "'");
        }
    }

    return rule;
}

}  // namespace sf
