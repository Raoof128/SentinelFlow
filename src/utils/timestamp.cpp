#include "sentinelflow/utils/timestamp.hpp"

#include <ctime>
#include <iomanip>
#include <sstream>

namespace sf {

std::string format_timestamp(std::chrono::system_clock::time_point tp) {
    auto time_t_val = std::chrono::system_clock::to_time_t(tp);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()) % 1000;
    std::tm tm_val;
    localtime_r(&time_t_val, &tm_val);
    std::ostringstream oss;
    oss << std::put_time(&tm_val, "%Y-%m-%d %H:%M:%S") << "." << std::setfill('0') << std::setw(3)
        << ms.count();
    return oss.str();
}

std::chrono::system_clock::time_point now() {
    return std::chrono::system_clock::now();
}

}  // namespace sf
