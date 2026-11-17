#include <string>

#include <gtest/gtest.h>

#include "sentinelflow/detection/dns_tunnel_detector.hpp"

using namespace sf;

namespace {

ParsedPacket dns_packet(IPv4Address src, const std::string& name, bool response,
                        std::chrono::system_clock::time_point ts) {
    ParsedPacket pkt;
    pkt.timestamp = ts;
    pkt.ipv4 = IPv4Header{};
    pkt.ipv4->src_ip = src;
    pkt.ipv4->dst_ip = 0x08080808;
    pkt.udp = UDPHeader{};
    pkt.dns = DNSHeader{};
    pkt.dns->is_response = response;
    pkt.dns->query_name = name;
    return pkt;
}

const std::string kLongName(60, 'a');

}  // namespace

TEST(DnsTunnelDetectorTest, AlertsOnEnoughLongQueries) {
    DnsTunnelDetector detector(50, 5, 60);
    auto t = std::chrono::system_clock::now();

    for (int i = 0; i < 4; ++i)
        EXPECT_FALSE(detector.check(dns_packet(1, kLongName, false, t)).has_value());

    auto alert = detector.check(dns_packet(1, kLongName, false, t));
    ASSERT_TRUE(alert.has_value());
    EXPECT_EQ(alert->sid, 5003u);
    EXPECT_EQ(alert->severity, AlertSeverity::HIGH);
}

TEST(DnsTunnelDetectorTest, IgnoresResponses) {
    DnsTunnelDetector detector(50, 5, 60);
    auto t = std::chrono::system_clock::now();

    for (int i = 0; i < 100; ++i)
        EXPECT_FALSE(detector.check(dns_packet(1, kLongName, true, t)).has_value());
    EXPECT_EQ(detector.tracked_sources(), 0u);
}

TEST(DnsTunnelDetectorTest, QueryAtTheLengthThresholdIsNotLong) {
    DnsTunnelDetector detector(50, 1, 60);
    auto t = std::chrono::system_clock::now();

    EXPECT_FALSE(detector.check(dns_packet(1, std::string(50, 'a'), false, t)).has_value());
    EXPECT_TRUE(detector.check(dns_packet(1, std::string(51, 'a'), false, t)).has_value());
}

TEST(DnsTunnelDetectorTest, SlowQueriesDoNotAccumulateAcrossWindows) {
    DnsTunnelDetector detector(50, 5, 60);
    auto t = std::chrono::system_clock::now();

    for (int i = 0; i < 50; ++i) {
        EXPECT_FALSE(detector.check(dns_packet(1, kLongName, false, t)).has_value());
        t += std::chrono::seconds(30);  // at most three fit in a 60 s window
    }
}

TEST(DnsTunnelDetectorTest, IdleSourcesAreEvicted) {
    DnsTunnelDetector detector(50, 5, 60);
    auto t = std::chrono::system_clock::now();

    for (uint32_t src = 1; src <= 100; ++src)
        detector.check(dns_packet(src, kLongName, false, t));
    EXPECT_EQ(detector.tracked_sources(), 100u);

    // One query from a new source after the window: the 100 idle sources are gone.
    detector.check(dns_packet(1000, kLongName, false, t + std::chrono::seconds(61)));
    EXPECT_EQ(detector.tracked_sources(), 1u);
}

TEST(DnsTunnelDetectorTest, TrackedSourcesAreCapped) {
    DnsTunnelDetector detector(50, 5, 60, /*max_tracked_sources=*/10);
    auto t = std::chrono::system_clock::now();

    for (uint32_t src = 1; src <= 1000; ++src)
        detector.check(dns_packet(src, kLongName, false, t));
    EXPECT_EQ(detector.tracked_sources(), 10u);
}
