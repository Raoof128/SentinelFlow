// Tool to generate sample .pcap files for testing
// Build:   cmake -B build && cmake --build build   (target: generate_samples)
// Run:     ./build/generate_samples   (from the repository root; it writes samples/*.pcap)

#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <vector>
#include <arpa/inet.h>

// PCAP file format structures
struct PcapFileHeader {
    uint32_t magic = 0xa1b2c3d4;
    uint16_t version_major = 2;
    uint16_t version_minor = 4;
    int32_t  thiszone = 0;
    uint32_t sigfigs = 0;
    uint32_t snaplen = 65535;
    uint32_t linktype = 1; // LINKTYPE_ETHERNET
};

struct PcapPacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

class PcapWriter {
public:
    explicit PcapWriter(const std::string& path) : file_(path, std::ios::binary) {
        PcapFileHeader fh;
        file_.write(reinterpret_cast<const char*>(&fh), sizeof(fh));
    }

    void write_packet(const std::vector<uint8_t>& data, uint32_t ts_sec, uint32_t ts_usec = 0) {
        PcapPacketHeader ph;
        ph.ts_sec = ts_sec;
        ph.ts_usec = ts_usec;
        ph.incl_len = data.size();
        ph.orig_len = data.size();
        file_.write(reinterpret_cast<const char*>(&ph), sizeof(ph));
        file_.write(reinterpret_cast<const char*>(data.data()), data.size());
    }

private:
    std::ofstream file_;
};

// Build an Ethernet + IPv4 + TCP packet
std::vector<uint8_t> make_tcp_packet(uint32_t src_ip, uint32_t dst_ip,
                                      uint16_t src_port, uint16_t dst_port,
                                      uint8_t flags) {
    std::vector<uint8_t> pkt(54, 0);
    // Ethernet
    pkt[0] = 0xFF; pkt[1] = 0xFF; pkt[2] = 0xFF; pkt[3] = 0xFF; pkt[4] = 0xFF; pkt[5] = 0xFF;
    pkt[6] = 0xAA; pkt[7] = 0xBB; pkt[8] = 0xCC; pkt[9] = 0xDD; pkt[10] = 0xEE; pkt[11] = 0xFF;
    pkt[12] = 0x08; pkt[13] = 0x00; // IPv4
    // IPv4
    pkt[14] = 0x45; // v4, ihl=5
    uint16_t total_len = htons(40);
    std::memcpy(&pkt[16], &total_len, 2);
    pkt[22] = 64; // TTL
    pkt[23] = 6;  // TCP
    uint32_t sip = htonl(src_ip), dip = htonl(dst_ip);
    std::memcpy(&pkt[26], &sip, 4);
    std::memcpy(&pkt[30], &dip, 4);
    // TCP
    uint16_t sp = htons(src_port), dp = htons(dst_port);
    std::memcpy(&pkt[34], &sp, 2);
    std::memcpy(&pkt[36], &dp, 2);
    pkt[46] = 0x50; // data offset = 5
    pkt[47] = flags;
    return pkt;
}

// Build an Ethernet + IPv4 + UDP + DNS query packet
std::vector<uint8_t> make_dns_packet(uint32_t src_ip, uint32_t dst_ip,
                                      const std::string& domain) {
    // Build DNS payload
    std::vector<uint8_t> dns_payload;
    dns_payload.push_back(0x00); dns_payload.push_back(0x01); // Transaction ID
    dns_payload.push_back(0x01); dns_payload.push_back(0x00); // Flags: standard query
    dns_payload.push_back(0x00); dns_payload.push_back(0x01); // Questions: 1
    dns_payload.push_back(0x00); dns_payload.push_back(0x00); // Answers: 0
    dns_payload.push_back(0x00); dns_payload.push_back(0x00); // Authority: 0
    dns_payload.push_back(0x00); dns_payload.push_back(0x00); // Additional: 0

    // Encode domain name
    size_t pos = 0;
    while (pos < domain.size()) {
        size_t dot = domain.find('.', pos);
        if (dot == std::string::npos) dot = domain.size();
        dns_payload.push_back(static_cast<uint8_t>(dot - pos));
        for (size_t i = pos; i < dot; ++i)
            dns_payload.push_back(static_cast<uint8_t>(domain[i]));
        pos = dot + 1;
    }
    dns_payload.push_back(0x00); // End of name
    dns_payload.push_back(0x00); dns_payload.push_back(0x01); // Type: A
    dns_payload.push_back(0x00); dns_payload.push_back(0x01); // Class: IN

    uint32_t total = 14 + 20 + 8 + dns_payload.size();
    std::vector<uint8_t> pkt(total, 0);

    // Ethernet
    pkt[12] = 0x08; pkt[13] = 0x00;
    // IPv4
    pkt[14] = 0x45;
    uint16_t ip_total = htons(20 + 8 + dns_payload.size());
    std::memcpy(&pkt[16], &ip_total, 2);
    pkt[22] = 64;
    pkt[23] = 17; // UDP
    uint32_t sip = htonl(src_ip), dip = htonl(dst_ip);
    std::memcpy(&pkt[26], &sip, 4);
    std::memcpy(&pkt[30], &dip, 4);
    // UDP
    uint16_t sp = htons(12345), dp = htons(53);
    std::memcpy(&pkt[34], &sp, 2);
    std::memcpy(&pkt[36], &dp, 2);
    uint16_t udp_len = htons(8 + dns_payload.size());
    std::memcpy(&pkt[38], &udp_len, 2);
    // DNS payload
    std::memcpy(&pkt[42], dns_payload.data(), dns_payload.size());

    return pkt;
}

// Build ICMP echo request
std::vector<uint8_t> make_icmp_packet(uint32_t src_ip, uint32_t dst_ip) {
    std::vector<uint8_t> pkt(42, 0); // 14 + 20 + 8
    pkt[12] = 0x08; pkt[13] = 0x00;
    pkt[14] = 0x45;
    uint16_t total = htons(28);
    std::memcpy(&pkt[16], &total, 2);
    pkt[22] = 64;
    pkt[23] = 1; // ICMP
    uint32_t sip = htonl(src_ip), dip = htonl(dst_ip);
    std::memcpy(&pkt[26], &sip, 4);
    std::memcpy(&pkt[30], &dip, 4);
    pkt[34] = 8; // Echo Request
    pkt[35] = 0; // Code
    return pkt;
}

int main() {
    uint32_t base_time = 1774051200;  // 2026-03-21 00:00:00 UTC, fixed so the files are reproducible

    // === normal_traffic.pcap ===
    {
        PcapWriter w("samples/normal_traffic.pcap");
        // Mix of normal HTTP, DNS, ICMP traffic
        for (int i = 0; i < 50; ++i) {
            w.write_packet(make_tcp_packet(0xC0A80164, 0x08080808, 50000 + i, 80, 0x02), base_time + i); // SYN
            w.write_packet(make_tcp_packet(0x08080808, 0xC0A80164, 80, 50000 + i, 0x12), base_time + i); // SYN-ACK
            w.write_packet(make_tcp_packet(0xC0A80164, 0x08080808, 50000 + i, 80, 0x10), base_time + i); // ACK
        }
        for (int i = 0; i < 20; ++i) {
            w.write_packet(make_dns_packet(0xC0A80164, 0x08080808, "example.com"), base_time + i);
        }
        for (int i = 0; i < 10; ++i) {
            w.write_packet(make_icmp_packet(0xC0A80164, 0x08080808), base_time + i);
        }
        std::cout << "Created samples/normal_traffic.pcap (180 packets)" << std::endl;
    }

    // === port_scan.pcap ===
    {
        PcapWriter w("samples/port_scan.pcap");
        // Single source scanning many ports on same target
        uint32_t attacker = 0x0A000101; // 10.0.1.1
        uint32_t target   = 0xC0A80164; // 192.168.1.100
        for (uint16_t port = 1; port <= 100; ++port) {
            w.write_packet(make_tcp_packet(attacker, target, 40000 + port, port, 0x02), base_time + port / 10);
        }
        std::cout << "Created samples/port_scan.pcap (100 packets - port scan)" << std::endl;
    }

    // === syn_flood.pcap ===
    {
        PcapWriter w("samples/syn_flood.pcap");
        uint32_t target = 0xC0A80164;
        // Many SYN packets from random sources to same target
        for (int i = 0; i < 500; ++i) {
            uint32_t src = 0x0A000001 + (i % 250); // Varied sources
            w.write_packet(make_tcp_packet(src, target, 30000 + i, 80, 0x02), base_time + i / 100);
        }
        std::cout << "Created samples/syn_flood.pcap (500 packets - SYN flood)" << std::endl;
    }

    std::cout << "All sample pcap files generated." << std::endl;
    return 0;
}
