#pragma once
#include "sentinelflow/capture/packet_capture.hpp"
#include <pcap.h>
#include <string>

namespace sf {

class LiveCapture : public PacketCapture {
public:
    LiveCapture(const std::string& interface, int snap_len = 65535);
    ~LiveCapture() override;

    bool open() override;
    bool set_filter(const std::string& filter_expr) override;
    void start(PacketCallback callback, int max_packets = -1) override;
    void stop() override;

private:
    std::string    interface_;
    int            snap_len_;
    pcap_t*        handle_;
    PacketCallback callback_;
};

} // namespace sf
