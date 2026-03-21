#pragma once
#include "sentinelflow/parser/packet.hpp"
#include <atomic>
#include <chrono>
#include <string>

namespace sf {

class TrafficStats {
public:
    TrafficStats();

    void record(const ParsedPacket& pkt);
    void print_summary() const;

    uint64_t total_packets() const { return total_packets_; }
    uint64_t tcp_count() const { return tcp_packets_; }
    uint64_t udp_count() const { return udp_packets_; }
    uint64_t icmp_count() const { return icmp_packets_; }
    uint64_t dns_count() const { return dns_packets_; }
    uint64_t arp_count() const { return arp_packets_; }
    uint64_t total_bytes() const { return total_bytes_; }

private:
    uint64_t total_packets_ = 0;
    uint64_t tcp_packets_ = 0;
    uint64_t udp_packets_ = 0;
    uint64_t icmp_packets_ = 0;
    uint64_t dns_packets_ = 0;
    uint64_t arp_packets_ = 0;
    uint64_t other_packets_ = 0;
    uint64_t total_bytes_ = 0;
    std::chrono::system_clock::time_point start_time_;
};

} // namespace sf
