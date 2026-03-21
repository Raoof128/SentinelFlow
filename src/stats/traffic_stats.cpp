#include "sentinelflow/stats/traffic_stats.hpp"
#include <iostream>
#include <iomanip>

namespace sf {

TrafficStats::TrafficStats()
    : start_time_(std::chrono::system_clock::now()) {}

void TrafficStats::record(const ParsedPacket& pkt) {
    ++total_packets_;
    total_bytes_ += pkt.raw_length;

    switch (pkt.highest_protocol()) {
        case Protocol::TCP:  ++tcp_packets_; break;
        case Protocol::UDP:  ++udp_packets_; break;
        case Protocol::ICMP: ++icmp_packets_; break;
        case Protocol::DNS:  ++dns_packets_; break;
        case Protocol::ARP:  ++arp_packets_; break;
        default:             ++other_packets_; break;
    }
}

void TrafficStats::print_summary() const {
    auto elapsed = std::chrono::system_clock::now() - start_time_;
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
    if (seconds == 0) seconds = 1;

    std::cout << "\n=== Traffic Statistics ===" << std::endl;
    std::cout << "Duration:    " << seconds << "s" << std::endl;
    std::cout << "Total:       " << total_packets_ << " packets ("
              << total_bytes_ << " bytes)" << std::endl;
    std::cout << "Throughput:  " << (total_packets_ / seconds) << " pkt/s, "
              << (total_bytes_ / seconds) << " bytes/s" << std::endl;
    std::cout << std::string(30, '-') << std::endl;
    std::cout << "TCP:         " << tcp_packets_ << std::endl;
    std::cout << "UDP:         " << udp_packets_ << std::endl;
    std::cout << "ICMP:        " << icmp_packets_ << std::endl;
    std::cout << "DNS:         " << dns_packets_ << std::endl;
    std::cout << "ARP:         " << arp_packets_ << std::endl;
    std::cout << "Other:       " << other_packets_ << std::endl;
}

} // namespace sf
