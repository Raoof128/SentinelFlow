#pragma once
#include <chrono>
#include <string>

namespace sf {

std::string format_timestamp(std::chrono::system_clock::time_point tp);
std::chrono::system_clock::time_point now();

} // namespace sf
