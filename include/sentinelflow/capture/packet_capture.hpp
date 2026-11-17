#pragma once
#include <chrono>
#include <cstdint>
#include <functional>
#include <string>

namespace sf {

using PacketCallback =
    std::function<void(const uint8_t*, uint32_t, std::chrono::system_clock::time_point)>;

class PacketCapture {
public:
    virtual ~PacketCapture() = default;
    virtual bool open() = 0;
    virtual bool set_filter(const std::string& filter_expr) = 0;
    virtual void start(PacketCallback callback, int max_packets = -1) = 0;
    virtual void stop() = 0;
};

}  // namespace sf
