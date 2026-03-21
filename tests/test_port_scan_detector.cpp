#include <gtest/gtest.h>
#include "sentinelflow/detection/port_scan_detector.hpp"

using namespace sf;

TEST(PortScanDetectorTest, DetectsPortScan) {
    PortScanDetector detector(5, 60);
    auto now = std::chrono::system_clock::now();

    for (uint16_t port = 1; port <= 4; ++port) {
        ParsedPacket pkt;
        pkt.timestamp = now;
        pkt.ipv4 = IPv4Header{};
        pkt.ipv4->src_ip = 0xC0A80101;
        pkt.ipv4->dst_ip = 0xC0A80102;
        pkt.tcp = TCPHeader{};
        pkt.tcp->dst_port = port;
        pkt.tcp->flags = TCP_SYN;
        EXPECT_FALSE(detector.check(pkt).has_value());
    }

    ParsedPacket pkt;
    pkt.timestamp = now;
    pkt.ipv4 = IPv4Header{};
    pkt.ipv4->src_ip = 0xC0A80101;
    pkt.ipv4->dst_ip = 0xC0A80102;
    pkt.tcp = TCPHeader{};
    pkt.tcp->dst_port = 5;
    pkt.tcp->flags = TCP_SYN;

    auto alert = detector.check(pkt);
    ASSERT_TRUE(alert.has_value());
    EXPECT_EQ(alert->severity, AlertSeverity::HIGH);
}

TEST(PortScanDetectorTest, IgnoresNonSYN) {
    PortScanDetector detector(2, 60);

    ParsedPacket pkt;
    pkt.timestamp = std::chrono::system_clock::now();
    pkt.ipv4 = IPv4Header{};
    pkt.ipv4->src_ip = 0xC0A80101;
    pkt.ipv4->dst_ip = 0xC0A80102;
    pkt.tcp = TCPHeader{};
    pkt.tcp->dst_port = 80;
    pkt.tcp->flags = TCP_ACK;

    EXPECT_FALSE(detector.check(pkt).has_value());
}

TEST(PortScanDetectorTest, IgnoresSYNACK) {
    PortScanDetector detector(2, 60);

    ParsedPacket pkt;
    pkt.timestamp = std::chrono::system_clock::now();
    pkt.ipv4 = IPv4Header{};
    pkt.tcp = TCPHeader{};
    pkt.tcp->dst_port = 80;
    pkt.tcp->flags = TCP_SYN | TCP_ACK;

    EXPECT_FALSE(detector.check(pkt).has_value());
}
