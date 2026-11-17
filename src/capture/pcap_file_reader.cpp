#include "sentinelflow/capture/pcap_file_reader.hpp"

#include <iostream>

#include "sentinelflow/capture/link_type.hpp"

namespace sf {

PcapFileReader::PcapFileReader(const std::string& filepath)
    : filepath_(filepath), handle_(nullptr) {}

PcapFileReader::~PcapFileReader() {
    if (handle_)
        pcap_close(handle_);
}

bool PcapFileReader::open() {
    char errbuf[PCAP_ERRBUF_SIZE];
    handle_ = pcap_open_offline(filepath_.c_str(), errbuf);
    if (!handle_) {
        std::cerr << "pcap_open_offline failed: " << errbuf << std::endl;
        return false;
    }
    if (!require_ethernet_link(handle_, filepath_)) {
        pcap_close(handle_);
        handle_ = nullptr;
        return false;
    }
    return true;
}

bool PcapFileReader::set_filter(const std::string& filter_expr) {
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

void PcapFileReader::start(PacketCallback callback, int max_packets) {
    callback_ = std::move(callback);
    pcap_loop(
        handle_, max_packets,
        [](u_char* user, const struct pcap_pkthdr* hdr, const u_char* data) {
            auto* self = reinterpret_cast<PcapFileReader*>(user);
            auto ts = std::chrono::system_clock::from_time_t(hdr->ts.tv_sec) +
                      std::chrono::microseconds(hdr->ts.tv_usec);
            self->callback_(data, hdr->caplen, ts);
        },
        reinterpret_cast<u_char*>(this));
}

void PcapFileReader::stop() {
    if (handle_)
        pcap_breakloop(handle_);
}

}  // namespace sf
