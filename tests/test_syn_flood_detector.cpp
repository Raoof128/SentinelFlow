#include <gtest/gtest.h>
#include "sentinelflow/detection/syn_flood_detector.hpp"

using namespace sf;

TEST(SynFloodDetectorTest, DetectsFlood) {
    SynFloodDetector detector(5, 10);
    auto now = std::chrono::system_clock::now();

    for (int i = 0; i < 4; ++i) {
        ParsedPacket pkt;
        pkt.timestamp = now;
        pkt.ipv4 = IPv4Header{};
        pkt.ipv4->src_ip = 0x0A000001 + i;
        pkt.ipv4->dst_ip = 0xC0A80101;
        pkt.tcp = TCPHeader{};
        pkt.tcp->flags = TCP_SYN;
        EXPECT_FALSE(detector.check(pkt).has_value());
    }

    ParsedPacket pkt;
    pkt.timestamp = now;
    pkt.ipv4 = IPv4Header{};
    pkt.ipv4->src_ip = 0x0A000005;
    pkt.ipv4->dst_ip = 0xC0A80101;
    pkt.tcp = TCPHeader{};
    pkt.tcp->flags = TCP_SYN;

    auto alert = detector.check(pkt);
    ASSERT_TRUE(alert.has_value());
    EXPECT_EQ(alert->severity, AlertSeverity::CRITICAL);
}

TEST(SynFloodDetectorTest, NoFloodBelowThreshold) {
    SynFloodDetector detector(10, 10);
    auto now = std::chrono::system_clock::now();

    for (int i = 0; i < 3; ++i) {
        ParsedPacket pkt;
        pkt.timestamp = now;
        pkt.ipv4 = IPv4Header{};
        pkt.ipv4->src_ip = 0x0A000001 + i;
        pkt.ipv4->dst_ip = 0xC0A80101;
        pkt.tcp = TCPHeader{};
        pkt.tcp->flags = TCP_SYN;
        EXPECT_FALSE(detector.check(pkt).has_value());
    }
}
