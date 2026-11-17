#include <chrono>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <vector>

#include "sentinelflow/parser/ethernet_parser.hpp"
#include "sentinelflow/parser/ip_parser.hpp"
#include "sentinelflow/parser/tcp_parser.hpp"

using namespace sf;

int main() {
    std::vector<uint8_t> fake_packet(54, 0);

    // Ethernet header
    fake_packet[12] = 0x08;
    fake_packet[13] = 0x00;

    // IPv4 header
    fake_packet[14] = 0x45;
    fake_packet[23] = 6;  // TCP
    fake_packet[26] = 192;
    fake_packet[27] = 168;
    fake_packet[28] = 1;
    fake_packet[29] = 100;
    fake_packet[30] = 10;
    fake_packet[31] = 0;
    fake_packet[32] = 0;
    fake_packet[33] = 1;

    // TCP header
    fake_packet[34] = 0x1F;
    fake_packet[35] = 0x90;
    fake_packet[36] = 0x00;
    fake_packet[37] = 0x50;
    fake_packet[46] = 0x50;
    fake_packet[47] = TCP_SYN | TCP_ACK;

    constexpr uint32_t NUM_PACKETS = 5'000'000;

    EthernetHeader eth;
    IPv4Header ip;
    TCPHeader tcp;

    auto start = std::chrono::high_resolution_clock::now();

    for (uint32_t i = 0; i < NUM_PACKETS; ++i) {
        parse_ethernet(fake_packet.data(), 54, eth);
        parse_ipv4(fake_packet.data() + 14, 40, ip);
        parse_tcp(fake_packet.data() + 34, 20, tcp);
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    double elapsed_s = elapsed_ms / 1000.0;
    double throughput = NUM_PACKETS / elapsed_s;

    std::cout << "=== SentinelFlow Benchmark ===" << std::endl;
    std::cout << "Packets processed: " << NUM_PACKETS << std::endl;
    std::cout << "Elapsed time:      " << elapsed_ms << " ms" << std::endl;
    std::cout << "Throughput:         " << std::fixed << static_cast<uint64_t>(throughput)
              << " packets/sec" << std::endl;
    std::cout << "Avg latency:        " << (elapsed_ms * 1000.0 / NUM_PACKETS) << " us/packet"
              << std::endl;

    return 0;
}
