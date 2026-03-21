#pragma once
#include "sentinelflow/utils/types.hpp"
#include <string>
#include <chrono>

namespace sf {

enum class AlertSeverity : uint8_t {
    LOW      = 1,
    MEDIUM   = 2,
    HIGH     = 3,
    CRITICAL = 4
};

struct Alert {
    uint32_t                              sid = 0;
    AlertSeverity                         severity = AlertSeverity::LOW;
    std::chrono::system_clock::time_point timestamp;
    IPv4Address                           src_ip = 0;
    IPv4Address                           dst_ip = 0;
    uint16_t                              src_port = 0;
    uint16_t                              dst_port = 0;
    std::string                           message;

    std::string severity_string() const {
        switch (severity) {
            case AlertSeverity::LOW:      return "LOW";
            case AlertSeverity::MEDIUM:   return "MEDIUM";
            case AlertSeverity::HIGH:     return "HIGH";
            case AlertSeverity::CRITICAL: return "CRITICAL";
        }
        return "UNKNOWN";
    }
};

} // namespace sf
