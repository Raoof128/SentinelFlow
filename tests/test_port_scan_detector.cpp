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

namespace {

ParsedPacket syn_to_port(IPv4Address src, IPv4Address dst, uint16_t port,
                         std::chrono::system_clock::time_point ts) {
    ParsedPacket pkt;
    pkt.timestamp = ts;
    pkt.ipv4 = IPv4Header{};
    pkt.ipv4->src_ip = src;
    pkt.ipv4->dst_ip = dst;
    pkt.tcp = TCPHeader{};
    pkt.tcp->dst_port = port;
    pkt.tcp->flags = TCP_SYN;
    return pkt;
}

}  // namespace

TEST(PortScanDetectorTest, SlowSenderDoesNotAccumulatePortsAcrossWindows) {
    // One SYN every 50 s to a new port, with a 60 s window: at most two ports are ever inside
    // the window. The old detector only cleared its port set when every timestamp had expired,
    // which never happens at this rate, so it alerted on the fifth port.
    PortScanDetector detector(5, 60);
    auto t = std::chrono::system_clock::now();

    for (uint16_t port = 1; port <= 40; ++port) {
        EXPECT_FALSE(detector.check(syn_to_port(0xC0A80101, 0xC0A80102, port, t)).has_value())
            << "alert on port " << port;
        t += std::chrono::seconds(50);
    }
}

TEST(PortScanDetectorTest, PortsSeenOutsideTheWindowAreNotCounted) {
    PortScanDetector detector(5, 60);
    auto t = std::chrono::system_clock::now();

    for (uint16_t port = 1; port <= 4; ++port)
        EXPECT_FALSE(detector.check(syn_to_port(1, 2, port, t)).has_value());

    // Fifth distinct port, but the first four are 61 s old.
    EXPECT_FALSE(detector.check(syn_to_port(1, 2, 5, t + std::chrono::seconds(61))).has_value());
}

TEST(PortScanDetectorTest, PortsInsideTheWindowStillCountWhenOldOnesExpire) {
    PortScanDetector detector(4, 60);
    auto t = std::chrono::system_clock::now();

    EXPECT_FALSE(detector.check(syn_to_port(1, 2, 1, t)).has_value());
    EXPECT_FALSE(detector.check(syn_to_port(1, 2, 2, t + std::chrono::seconds(30))).has_value());
    EXPECT_FALSE(detector.check(syn_to_port(1, 2, 3, t + std::chrono::seconds(70))).has_value());
    // Ports 2 and 3 are still inside the window; 1 has expired. 4 and 5 make four live ports.
    EXPECT_FALSE(detector.check(syn_to_port(1, 2, 4, t + std::chrono::seconds(71))).has_value());
    EXPECT_TRUE(detector.check(syn_to_port(1, 2, 5, t + std::chrono::seconds(72))).has_value());
}

TEST(PortScanDetectorTest, RepeatedSynsToOnePortAreOnePort) {
    PortScanDetector detector(3, 60);
    auto t = std::chrono::system_clock::now();

    for (int i = 0; i < 50; ++i)
        EXPECT_FALSE(detector.check(syn_to_port(1, 2, 80, t)).has_value());
}

TEST(PortScanDetectorTest, IdlePairsAreEvicted) {
    PortScanDetector detector(5, 60);
    auto t = std::chrono::system_clock::now();

    for (uint32_t src = 1; src <= 100; ++src)
        detector.check(syn_to_port(src, 2, 80, t));
    EXPECT_EQ(detector.tracked_pairs(), 100u);

    // One SYN from a new source after the window: the 100 idle pairs are gone.
    detector.check(syn_to_port(1000, 2, 80, t + std::chrono::seconds(61)));
    EXPECT_EQ(detector.tracked_pairs(), 1u);
}

TEST(PortScanDetectorTest, ActivePairsSurviveEviction) {
    PortScanDetector detector(5, 60);
    auto t = std::chrono::system_clock::now();

    // A pair that keeps sending stays tracked while others age out.
    for (int i = 0; i < 10; ++i) {
        detector.check(syn_to_port(1, 2, 80, t + std::chrono::seconds(i * 20)));
        detector.check(syn_to_port(100 + i, 2, 80, t + std::chrono::seconds(i * 20)));
    }
    // Pair 1 plus the pairs last seen at or after the cutoff (now - 60 s = t + 120 s): i = 6..9.
    EXPECT_EQ(detector.tracked_pairs(), 5u);
}

TEST(PortScanDetectorTest, TrackedPairsAreCapped) {
    PortScanDetector detector(5, 60, /*max_tracked_pairs=*/10);
    auto t = std::chrono::system_clock::now();

    for (uint32_t src = 1; src <= 1000; ++src)
        detector.check(syn_to_port(src, 2, 80, t));
    EXPECT_EQ(detector.tracked_pairs(), 10u);
}

TEST(PortScanDetectorTest, CapDropsTheLeastRecentlyActivePair) {
    PortScanDetector detector(3, 60, /*max_tracked_pairs=*/2);
    auto t = std::chrono::system_clock::now();

    detector.check(syn_to_port(1, 2, 1, t));
    detector.check(syn_to_port(2, 2, 1, t));
    detector.check(syn_to_port(1, 2, 2, t));  // pair 1 is now the most recent
    detector.check(syn_to_port(3, 2, 1, t));  // evicts pair 2, not pair 1

    // Pair 1 still has ports 1 and 2; one more port reaches the threshold of 3.
    EXPECT_TRUE(detector.check(syn_to_port(1, 2, 3, t)).has_value());
}

TEST(PortScanDetectorTest, OutOfOrderTimestampsDoNotResurrectExpiredPorts) {
    PortScanDetector detector(3, 60);
    auto t = std::chrono::system_clock::now();

    detector.check(syn_to_port(1, 2, 1, t + std::chrono::seconds(100)));
    // A packet stamped earlier than the newest one seen is treated as arriving "now".
    detector.check(syn_to_port(1, 2, 2, t));
    EXPECT_TRUE(detector.check(syn_to_port(1, 2, 3, t)).has_value());
}

TEST(PortScanDetectorTest, NearThresholdPairSurvivesAFloodOfSingleProbeSources) {
    // An attacker sprays spoofed sources to fill the table and push a slow scanner's state out.
    // The scanner is the oldest record but the furthest advanced, so it must not be the victim.
    PortScanDetector detector(5, 60, /*max_tracked_pairs=*/10);
    auto t = std::chrono::system_clock::now();

    for (uint16_t port = 1; port <= 4; ++port)
        detector.check(syn_to_port(1, 2, port, t));
    for (uint32_t src = 100; src < 1100; ++src)
        detector.check(syn_to_port(src, 2, 80, t));
    EXPECT_GT(detector.capacity_evictions(), 900u);

    EXPECT_TRUE(detector.check(syn_to_port(1, 2, 5, t)).has_value());
}

TEST(PortScanDetectorTest, ExpiredPairsAreEvictedBeforeLiveOnesAtCapacity) {
    PortScanDetector detector(5, 60, /*max_tracked_pairs=*/3);
    auto t = std::chrono::system_clock::now();

    detector.check(syn_to_port(1, 2, 1, t));
    detector.check(syn_to_port(2, 2, 1, t));
    detector.check(syn_to_port(3, 2, 1, t + std::chrono::seconds(50)));
    detector.check(syn_to_port(4, 2, 1, t + std::chrono::seconds(61)));

    EXPECT_EQ(detector.tracked_pairs(), 2u);       // pairs 3 and 4
    EXPECT_EQ(detector.capacity_evictions(), 0u);  // the two dropped had expired
}

// Documents a known limitation (see README, "Packet time is trusted"): detector time never runs
// backwards, so a single packet stamped far in the future becomes "now" for everything after
// it and the window stops sliding. If this test starts failing because the detector has learnt
// to distrust such a timestamp, update the README and delete or invert the test.
TEST(PortScanDetectorTest, KnownLimitationAFarFutureTimestampFreezesTheWindow) {
    PortScanDetector detector(5, 60);
    auto t = std::chrono::system_clock::now();

    // One bogus packet from an unrelated source, stamped ten years ahead.
    detector.check(syn_to_port(9, 9, 1, t + std::chrono::hours(24 * 365 * 10)));

    // Five ports, one per hour: far too slow to be a scan in a 60-second window.
    std::optional<Alert> alert;
    for (uint16_t port = 1; port <= 5; ++port)
        alert = detector.check(syn_to_port(1, 2, port, t + std::chrono::hours(port)));

    EXPECT_TRUE(alert.has_value());  // alerts anyway: every probe is treated as simultaneous
}
