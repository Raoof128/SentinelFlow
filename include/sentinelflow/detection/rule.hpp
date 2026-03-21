#pragma once
#include <string>
#include <cstdint>
#include <optional>

namespace sf {

struct Rule {
    uint32_t    sid;
    std::string action;
    std::string protocol;
    std::string src_ip;
    std::string src_port;
    std::string dst_ip;
    std::string dst_port;
    std::string message;

    std::optional<uint8_t>  tcp_flags;
    std::optional<uint32_t> threshold_count;
    std::optional<uint32_t> threshold_seconds;
    std::optional<uint32_t> dns_query_min_len;
    std::optional<std::string> content;
};

} // namespace sf
