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

namespace {

ParsedPacket syn_from(IPv4Address src, IPv4Address dst, std::chrono::system_clock::time_point ts) {
    ParsedPacket pkt;
    pkt.timestamp = ts;
    pkt.ipv4 = IPv4Header{};
    pkt.ipv4->src_ip = src;
    pkt.ipv4->dst_ip = dst;
    pkt.tcp = TCPHeader{};
    pkt.tcp->flags = TCP_SYN;
    return pkt;
}

}  // namespace

TEST(SynFloodDetectorTest, OneAlertPerWindowDuringASustainedFlood) {
    // The old detector alerted on every threshold-th SYN, so 50 SYNs at threshold 5 gave 10
    // alerts.
    SynFloodDetector detector(5, 10);
    auto t = std::chrono::system_clock::now();

    int alerts = 0;
    for (uint32_t i = 0; i < 50; ++i) {
        if (detector.check(syn_from(0x0A000001 + i, 0xC0A80101, t)))
            ++alerts;
    }
    EXPECT_EQ(alerts, 1);
}

TEST(SynFloodDetectorTest, AlertsAgainOnceTheWindowHasPassed) {
    SynFloodDetector detector(5, 10);
    auto t = std::chrono::system_clock::now();

    int alerts = 0;
    for (uint32_t i = 0; i < 20; ++i) {
        if (detector.check(syn_from(0x0A000001 + i, 0xC0A80101, t)))
            ++alerts;
    }
    EXPECT_EQ(alerts, 1);

    // The flood continues 11 s later: a second alert, and only one.
    for (uint32_t i = 0; i < 20; ++i) {
        if (detector.check(syn_from(0x0A000001 + i, 0xC0A80101, t + std::chrono::seconds(11))))
            ++alerts;
    }
    EXPECT_EQ(alerts, 2);
}

TEST(SynFloodDetectorTest, TargetsAreCountedSeparately) {
    SynFloodDetector detector(5, 10);
    auto t = std::chrono::system_clock::now();

    // Four SYNs each to two targets: neither reaches the threshold.
    for (uint32_t i = 0; i < 4; ++i) {
        EXPECT_FALSE(detector.check(syn_from(1 + i, 0xC0A80101, t)).has_value());
        EXPECT_FALSE(detector.check(syn_from(1 + i, 0xC0A80102, t)).has_value());
    }
}

TEST(SynFloodDetectorTest, SlowSynsNeverReachTheThreshold) {
    SynFloodDetector detector(5, 10);
    auto t = std::chrono::system_clock::now();

    // One SYN every 3 s: at most four fit in a 10 s window.
    for (uint32_t i = 0; i < 100; ++i) {
        EXPECT_FALSE(detector.check(syn_from(1, 0xC0A80101, t)).has_value());
        t += std::chrono::seconds(3);
    }
}

TEST(SynFloodDetectorTest, IdleTargetsAreEvicted) {
    SynFloodDetector detector(5, 10);
    auto t = std::chrono::system_clock::now();

    for (uint32_t dst = 1; dst <= 100; ++dst)
        detector.check(syn_from(1, dst, t));
    EXPECT_EQ(detector.tracked_targets(), 100u);

    detector.check(syn_from(1, 1000, t + std::chrono::seconds(11)));
    EXPECT_EQ(detector.tracked_targets(), 1u);
}

TEST(SynFloodDetectorTest, TrackedTargetsAreCapped) {
    SynFloodDetector detector(5, 10, /*max_tracked_targets=*/10);
    auto t = std::chrono::system_clock::now();

    for (uint32_t dst = 1; dst <= 1000; ++dst)
        detector.check(syn_from(1, dst, t));
    EXPECT_EQ(detector.tracked_targets(), 10u);
}

TEST(SynFloodDetectorTest, ThresholdOfOneAlertsOncePerWindow) {
    SynFloodDetector detector(1, 10);
    auto t = std::chrono::system_clock::now();

    EXPECT_TRUE(detector.check(syn_from(1, 2, t)).has_value());
    EXPECT_FALSE(detector.check(syn_from(1, 2, t + std::chrono::seconds(5))).has_value());
    EXPECT_TRUE(detector.check(syn_from(1, 2, t + std::chrono::seconds(10))).has_value());
}
