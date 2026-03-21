#include "sentinelflow/capture/live_capture.hpp"
#include <iostream>

namespace sf {

LiveCapture::LiveCapture(const std::string& interface, int snap_len)
    : interface_(interface), snap_len_(snap_len), handle_(nullptr) {}

LiveCapture::~LiveCapture() {
    if (handle_) pcap_close(handle_);
}

bool LiveCapture::open() {
    char errbuf[PCAP_ERRBUF_SIZE];
    handle_ = pcap_open_live(
        interface_.c_str(),
        snap_len_,
        1,
        1000,
        errbuf
    );
    if (!handle_) {
        std::cerr << "pcap_open_live failed: " << errbuf << std::endl;
        return false;
    }
    return true;
}

bool LiveCapture::set_filter(const std::string& filter_expr) {
    struct bpf_program fp;
    if (pcap_compile(handle_, &fp, filter_expr.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1)
        return false;
    if (pcap_setfilter(handle_, &fp) == -1) {
        pcap_freecode(&fp);
        return false;
    }
    pcap_freecode(&fp);
    return true;
}

void LiveCapture::start(PacketCallback callback, int max_packets) {
    callback_ = std::move(callback);
    pcap_loop(handle_, max_packets,
        [](u_char* user, const struct pcap_pkthdr* hdr, const u_char* data) {
            auto* self = reinterpret_cast<LiveCapture*>(user);
            auto ts = std::chrono::system_clock::from_time_t(hdr->ts.tv_sec)
                     + std::chrono::microseconds(hdr->ts.tv_usec);
            self->callback_(data, hdr->caplen, ts);
        },
        reinterpret_cast<u_char*>(this)
    );
}

void LiveCapture::stop() {
    if (handle_) pcap_breakloop(handle_);
}

} // namespace sf
