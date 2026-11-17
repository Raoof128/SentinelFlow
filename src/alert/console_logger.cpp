#include "sentinelflow/alert/console_logger.hpp"

#include <iostream>

#include "sentinelflow/utils/timestamp.hpp"

namespace sf {

void ConsoleLogger::emit(const Alert& alert) {
    // ANSI color codes
    const char* color;
    switch (alert.severity) {
        case AlertSeverity::LOW:
            color = "\033[32m";
            break;  // Green
        case AlertSeverity::MEDIUM:
            color = "\033[33m";
            break;  // Yellow
        case AlertSeverity::HIGH:
            color = "\033[31m";
            break;  // Red
        case AlertSeverity::CRITICAL:
            color = "\033[1;31m";
            break;  // Bold Red
        default:
            color = "\033[0m";
            break;
    }
    const char* reset = "\033[0m";

    std::cout << color << "[" << alert.severity_string() << "]" << reset << " [SID:" << alert.sid
              << "] " << format_timestamp(alert.timestamp) << " " << ip_to_string(alert.src_ip);
    if (alert.src_port)
        std::cout << ":" << alert.src_port;
    std::cout << " -> " << ip_to_string(alert.dst_ip);
    if (alert.dst_port)
        std::cout << ":" << alert.dst_port;
    std::cout << " | " << alert.message << std::endl;
}

}  // namespace sf
