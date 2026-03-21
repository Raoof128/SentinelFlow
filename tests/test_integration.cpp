#include <gtest/gtest.h>
#include <cstring>
#include <arpa/inet.h>
#include "sentinelflow/parser/ethernet_parser.hpp"
#include "sentinelflow/parser/ip_parser.hpp"
#include "sentinelflow/parser/tcp_parser.hpp"
#include "sentinelflow/detection/detection_engine.hpp"
#include "sentinelflow/alert/alert_manager.hpp"

using namespace sf;

class IntegrationTest : public ::testing::Test {
protected:
    // Build a minimal TCP SYN packet (Ethernet + IPv4 + TCP = 54 bytes)
    std::vector<uint8_t> make_syn_packet(uint32_t src_ip, uint32_t dst_ip,
                                          uint16_t dst_port) {
        std::vector<uint8_t> pkt(54, 0);
        // Ethernet: IPv4
        pkt[12] = 0x08; pkt[13] = 0x00;
        // IPv4
        pkt[14] = 0x45; // v4, ihl=5
        pkt[23] = 6;    // TCP
        uint32_t src_n = htonl(src_ip);
        uint32_t dst_n = htonl(dst_ip);
        std::memcpy(&pkt[26], &src_n, 4);
        std::memcpy(&pkt[30], &dst_n, 4);
        // TCP
        uint16_t dp = htons(dst_port);
        std::memcpy(&pkt[36], &dp, 2);
        pkt[46] = 0x50; // data offset = 5
        pkt[47] = TCP_SYN;
        return pkt;
    }

    ParsedPacket parse_full(const uint8_t* data, uint32_t length) {
        ParsedPacket pkt;
        pkt.timestamp = std::chrono::system_clock::now();
        pkt.raw_data = data;
        pkt.raw_length = length;

        parse_ethernet(data, length, pkt.ethernet);
        if (pkt.ethernet.ether_type == 0x0800) {
            IPv4Header ip;
            if (parse_ipv4(data + 14, length - 14, ip)) {
                pkt.ipv4 = ip;
                uint32_t offset = 14 + ip.ihl * 4;
                if (ip.protocol == 6) {
                    TCPHeader tcp;
                    if (parse_tcp(data + offset, length - offset, tcp))
                        pkt.tcp = tcp;
                }
            }
        }
        return pkt;
    }
};

TEST_F(IntegrationTest, FullPipelineParseAndDetect) {
    auto raw = make_syn_packet(0xC0A80101, 0xC0A80102, 22);
    auto pkt = parse_full(raw.data(), raw.size());

    ASSERT_TRUE(pkt.ipv4.has_value());
    ASSERT_TRUE(pkt.tcp.has_value());
    EXPECT_EQ(pkt.tcp->dst_port, 22);
    EXPECT_TRUE(pkt.tcp->flags & TCP_SYN);
}

TEST_F(IntegrationTest, PortScanDetection) {
    DetectionEngine engine;
    // No rules file needed for stateful detectors

    std::vector<Alert> all_alerts;
    auto now = std::chrono::system_clock::now();

    for (uint16_t port = 1; port <= 20; ++port) {
        auto raw = make_syn_packet(0xC0A80101, 0xC0A80102, port);
        auto pkt = parse_full(raw.data(), raw.size());
        pkt.timestamp = now;
        auto alerts = engine.analyze(pkt);
        all_alerts.insert(all_alerts.end(), alerts.begin(), alerts.end());
    }

    EXPECT_FALSE(all_alerts.empty());
    bool found_port_scan = false;
    for (const auto& a : all_alerts) {
        if (a.sid == 5001) found_port_scan = true;
    }
    EXPECT_TRUE(found_port_scan);
}
