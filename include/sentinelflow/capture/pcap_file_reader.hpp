#pragma once
#include "sentinelflow/capture/packet_capture.hpp"
#include <pcap.h>
#include <string>

namespace sf {

class PcapFileReader : public PacketCapture {
public:
    explicit PcapFileReader(const std::string& filepath);
    ~PcapFileReader() override;

    bool open() override;
    bool set_filter(const std::string& filter_expr) override;
    void start(PacketCallback callback, int max_packets = -1) override;
    void stop() override;

private:
    std::string    filepath_;
    pcap_t*        handle_;
    PacketCallback callback_;
};

} // namespace sf
