#include <string>

#include <gtest/gtest.h>

#include "sentinelflow/detection/dns_tunnel_detector.hpp"

using namespace sf;

namespace {

// A DNS message. `from_server` sets the ports as a reply would have them (53 -> 40000);
// otherwise it is sent to port 53. `qr` is the DNS QR bit and is independent of the ports.
ParsedPacket dns_packet(IPv4Address src, const std::string& name, bool from_server, bool qr,
                        std::chrono::system_clock::time_point ts) {
    ParsedPacket pkt;
    pkt.timestamp = ts;
    pkt.ipv4 = IPv4Header{};
    pkt.ipv4->src_ip = src;
    pkt.ipv4->dst_ip = 0x08080808;
    pkt.udp = UDPHeader{};
    pkt.udp->src_port = from_server ? 53 : 40000;
    pkt.udp->dst_port = from_server ? 40000 : 53;
    pkt.dns = DNSHeader{};
    pkt.dns->is_response = qr;
    pkt.dns->query_name = name;
    return pkt;
}

ParsedPacket query(IPv4Address src, const std::string& name,
                   std::chrono::system_clock::time_point ts) {
    return dns_packet(src, name, false, false, ts);
}

const std::string kLongName(60, 'a');

}  // namespace

TEST(DnsTunnelDetectorTest, AlertsOnEnoughLongQueries) {
    DnsTunnelDetector detector(50, 5, 60);
    auto t = std::chrono::system_clock::now();

    for (int i = 0; i < 4; ++i)
        EXPECT_FALSE(detector.check(query(1, kLongName, t)).has_value());

    auto alert = detector.check(query(1, kLongName, t));
    ASSERT_TRUE(alert.has_value());
    EXPECT_EQ(alert->sid, 5003u);
    EXPECT_EQ(alert->severity, AlertSeverity::HIGH);
}

TEST(DnsTunnelDetectorTest, IgnoresResponses) {
    DnsTunnelDetector detector(50, 5, 60);
    auto t = std::chrono::system_clock::now();

    for (int i = 0; i < 100; ++i)
        EXPECT_FALSE(detector.check(dns_packet(1, kLongName, true, true, t)).has_value());
    EXPECT_EQ(detector.tracked_sources(), 0u);
}

TEST(DnsTunnelDetectorTest, QueryAtTheLengthThresholdIsNotLong) {
    DnsTunnelDetector detector(50, 1, 60);
    auto t = std::chrono::system_clock::now();

    EXPECT_FALSE(detector.check(query(1, std::string(50, 'a'), t)).has_value());
    EXPECT_TRUE(detector.check(query(1, std::string(51, 'a'), t)).has_value());
}

TEST(DnsTunnelDetectorTest, SlowQueriesDoNotAccumulateAcrossWindows) {
    DnsTunnelDetector detector(50, 5, 60);
    auto t = std::chrono::system_clock::now();

    for (int i = 0; i < 50; ++i) {
        EXPECT_FALSE(detector.check(query(1, kLongName, t)).has_value());
        t += std::chrono::seconds(30);  // at most three fit in a 60 s window
    }
}

TEST(DnsTunnelDetectorTest, IdleSourcesAreEvicted) {
    DnsTunnelDetector detector(50, 5, 60);
    auto t = std::chrono::system_clock::now();

    for (uint32_t src = 1; src <= 100; ++src)
        detector.check(query(src, kLongName, t));
    EXPECT_EQ(detector.tracked_sources(), 100u);

    // One query from a new source after the window: the 100 idle sources are gone.
    detector.check(query(1000, kLongName, t + std::chrono::seconds(61)));
    EXPECT_EQ(detector.tracked_sources(), 1u);
}

TEST(DnsTunnelDetectorTest, NearThresholdSourceSurvivesAFloodOfSingleQuerySources) {
    DnsTunnelDetector detector(50, 5, 60, /*max_tracked_sources=*/10);
    auto t = std::chrono::system_clock::now();

    for (int i = 0; i < 4; ++i)
        detector.check(query(1, kLongName, t));
    for (uint32_t src = 100; src < 1100; ++src)
        detector.check(query(src, kLongName, t));
    EXPECT_GT(detector.capacity_evictions(), 900u);

    EXPECT_TRUE(detector.check(query(1, kLongName, t)).has_value());
}

TEST(DnsTunnelDetectorTest, TrackedSourcesAreCapped) {
    DnsTunnelDetector detector(50, 5, 60, /*max_tracked_sources=*/10);
    auto t = std::chrono::system_clock::now();

    for (uint32_t src = 1; src <= 1000; ++src)
        detector.check(query(src, kLongName, t));
    EXPECT_EQ(detector.tracked_sources(), 10u);
}

TEST(DnsTunnelDetectorTest, QueryThatSetsTheResponseBitIsStillCounted) {
    // The QR bit is the sender's to set. A client exfiltrating over DNS could mark every query
    // as a response to opt out of detection if the detector trusted it.
    DnsTunnelDetector detector(50, 5, 60);
    auto t = std::chrono::system_clock::now();

    for (int i = 0; i < 4; ++i)
        EXPECT_FALSE(detector.check(dns_packet(1, kLongName, false, true, t)).has_value());
    EXPECT_TRUE(detector.check(dns_packet(1, kLongName, false, true, t)).has_value());
}

TEST(DnsTunnelDetectorTest, ReplyFromPortFiftyThreeIsIgnoredWhateverItsResponseBit) {
    DnsTunnelDetector detector(50, 5, 60);
    auto t = std::chrono::system_clock::now();

    for (int i = 0; i < 100; ++i) {
        EXPECT_FALSE(detector.check(dns_packet(1, kLongName, true, true, t)).has_value());
        EXPECT_FALSE(detector.check(dns_packet(1, kLongName, true, false, t)).has_value());
    }
    EXPECT_EQ(detector.tracked_sources(), 0u);
}

TEST(DnsTunnelDetectorTest, MessageBetweenTwoPortFiftyThreesIsAnalysed) {
    DnsTunnelDetector detector(50, 1, 60);
    auto t = std::chrono::system_clock::now();

    auto pkt = query(1, kLongName, t);
    pkt.udp->src_port = 53;
    pkt.udp->dst_port = 53;
    EXPECT_TRUE(detector.check(pkt).has_value());
}
