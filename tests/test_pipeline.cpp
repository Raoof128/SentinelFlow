// End-to-end tests: raw Ethernet frames built in memory go through the library pipeline
// (framing, parsing, detection, alerting) and the alerts that come out are asserted.
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "sentinelflow/alert/alert_manager.hpp"
#include "sentinelflow/detection/detection_engine.hpp"
#include "sentinelflow/detection/rule_parser.hpp"
#include "sentinelflow/pipeline/pipeline.hpp"
#include "sentinelflow/stats/traffic_stats.hpp"

using namespace sf;

namespace {

constexpr IPv4Address kClient = 0x0A000001;  // 10.0.0.1
constexpr IPv4Address kServer = 0xC0A80164;  // 192.168.1.100
constexpr IPv4Address kResolver = 0x08080808;

void put16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value & 0xFF));
}

void put32(std::vector<uint8_t>& out, uint32_t value) {
    put16(out, static_cast<uint16_t>(value >> 16));
    put16(out, static_cast<uint16_t>(value & 0xFFFF));
}

// A TCP segment: 20-byte header (data offset in 32-bit words) followed by the payload.
std::vector<uint8_t> tcp_segment(uint16_t src_port, uint16_t dst_port, uint8_t flags,
                                 const std::string& payload = "", uint8_t data_offset = 5) {
    std::vector<uint8_t> seg;
    put16(seg, src_port);
    put16(seg, dst_port);
    put32(seg, 1);  // sequence number
    put32(seg, 0);  // acknowledgement number
    seg.push_back(static_cast<uint8_t>(data_offset << 4));
    seg.push_back(flags);
    put16(seg, 8192);  // window
    put16(seg, 0);     // checksum
    put16(seg, 0);     // urgent pointer
    seg.insert(seg.end(), payload.begin(), payload.end());
    return seg;
}

std::vector<uint8_t> udp_datagram(uint16_t src_port, uint16_t dst_port,
                                  const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> dgram;
    put16(dgram, src_port);
    put16(dgram, dst_port);
    put16(dgram, static_cast<uint16_t>(8 + payload.size()));
    put16(dgram, 0);  // checksum
    dgram.insert(dgram.end(), payload.begin(), payload.end());
    return dgram;
}

// A DNS message with one question for `name` (type A, class IN).
std::vector<uint8_t> dns_message(const std::string& name, bool response) {
    std::vector<uint8_t> msg;
    put16(msg, 0x1234);
    put16(msg, response ? 0x8180 : 0x0100);
    put16(msg, 1);  // questions
    put16(msg, response ? 1 : 0);
    put16(msg, 0);
    put16(msg, 0);
    size_t pos = 0;
    while (pos < name.size()) {
        size_t dot = name.find('.', pos);
        if (dot == std::string::npos)
            dot = name.size();
        msg.push_back(static_cast<uint8_t>(dot - pos));
        msg.insert(msg.end(), name.begin() + pos, name.begin() + dot);
        pos = dot + 1;
    }
    msg.push_back(0);
    put16(msg, 1);
    put16(msg, 1);
    return msg;
}

struct FrameOptions {
    uint16_t flags_fragment = 0;  // IPv4 flags and fragment offset
    size_t min_frame_size = 0;    // pad the frame to at least this size (Ethernet pads to 60)
    uint8_t pad_byte = 0;
    bool zero_total_length = false;
};

// Ethernet + IPv4 (20-byte header) + `l4`.
std::vector<uint8_t> ipv4_frame(uint8_t protocol, IPv4Address src, IPv4Address dst,
                                const std::vector<uint8_t>& l4, FrameOptions opts = {}) {
    std::vector<uint8_t> frame(12, 0xAA);  // MAC addresses
    put16(frame, 0x0800);
    frame.push_back(0x45);  // version 4, IHL 5
    frame.push_back(0);     // TOS
    put16(frame, opts.zero_total_length ? 0 : static_cast<uint16_t>(20 + l4.size()));
    put16(frame, 1);  // identification
    put16(frame, opts.flags_fragment);
    frame.push_back(64);  // TTL
    frame.push_back(protocol);
    put16(frame, 0);  // checksum
    put32(frame, src);
    put32(frame, dst);
    frame.insert(frame.end(), l4.begin(), l4.end());
    if (frame.size() < opts.min_frame_size)
        frame.resize(opts.min_frame_size, opts.pad_byte);
    return frame;
}

std::vector<uint8_t> tcp_frame(IPv4Address src, IPv4Address dst, uint16_t dst_port, uint8_t flags,
                               const std::string& payload = "", FrameOptions opts = {}) {
    return ipv4_frame(6, src, dst, tcp_segment(40000, dst_port, flags, payload), opts);
}

// `qr_response` is the DNS QR bit; `from_server` is the transport direction (53 -> 40000).
std::vector<uint8_t> dns_frame(IPv4Address src, IPv4Address dst, const std::string& name,
                               bool qr_response, bool from_server) {
    const auto msg = dns_message(name, qr_response);
    return from_server ? ipv4_frame(17, src, dst, udp_datagram(53, 40000, msg))
                       : ipv4_frame(17, src, dst, udp_datagram(40000, 53, msg));
}

// Collects every alert the pipeline raises.
class CollectingOutput : public AlertOutput {
public:
    explicit CollectingOutput(std::vector<Alert>* sink) : sink_(sink) {}
    void emit(const Alert& alert) override { sink_->push_back(alert); }

private:
    std::vector<Alert>* sink_;
};

// A detection engine, alert sink and clock wired to the library pipeline.
class PipelineHarness {
public:
    explicit PipelineHarness(const std::vector<std::string>& rule_lines = {}) {
        std::vector<Rule> rules;
        for (const auto& line : rule_lines) {
            std::string error;
            auto rule = RuleParser::parse_line(line, &error);
            EXPECT_TRUE(rule.has_value()) << line << ": " << error;
            if (rule)
                rules.push_back(*rule);
        }
        engine_.apply_rules(rules);
        alerts_.add_output(std::make_unique<CollectingOutput>(&collected_));
    }

    void send(const std::vector<uint8_t>& frame, bool verbose = false) {
        process_packet(frame.data(), static_cast<uint32_t>(frame.size()), now_, engine_, alerts_,
                       stats_, verbose);
        now_ += std::chrono::milliseconds(1);
    }

    void advance(std::chrono::seconds seconds) { now_ += seconds; }

    size_t count(uint32_t sid) const {
        size_t n = 0;
        for (const auto& a : collected_)
            if (a.sid == sid)
                ++n;
        return n;
    }

    const std::vector<Alert>& alerts() const { return collected_; }
    const TrafficStats& stats() const { return stats_; }

private:
    DetectionEngine engine_;
    AlertManager alerts_;
    TrafficStats stats_;
    std::vector<Alert> collected_;
    std::chrono::system_clock::time_point now_ =
        std::chrono::system_clock::from_time_t(1'800'000'000);
};

const std::vector<std::string> kRules = {
    R"(alert tcp any any -> any 22 (msg:"SSH connection attempt"; sid:1001;))",
    R"(alert tcp any any -> any any (flags:S; threshold:20,60; msg:"Possible SYN flood"; sid:2001;))",
    R"(alert udp any any -> any 53 (dns_query_len:>50; msg:"Possible DNS tunnelling"; sid:3001;))",
    R"(alert any any any -> any 22 (msg:"Anything to port 22"; sid:1100;))",
};

}  // namespace

TEST(PipelineTest, SynToPortTwentyTwoTriggersTheSshRule) {
    PipelineHarness harness(kRules);

    harness.send(tcp_frame(kClient, kServer, 22, TCP_SYN));

    EXPECT_EQ(harness.count(1001), 1u);
    EXPECT_EQ(harness.count(1100), 1u);  // the protocol-any rule sees the TCP packet too
    EXPECT_EQ(harness.alerts().size(), 2u);
    EXPECT_EQ(harness.alerts()[0].dst_port, 22);
    EXPECT_EQ(harness.alerts()[0].src_ip, kClient);
    EXPECT_EQ(harness.alerts()[0].dst_ip, kServer);
}

TEST(PipelineTest, SynToAnotherPortRaisesNothing) {
    PipelineHarness harness(kRules);

    harness.send(tcp_frame(kClient, kServer, 8080, TCP_SYN));

    EXPECT_TRUE(harness.alerts().empty());
    EXPECT_EQ(harness.stats().tcp_count(), 1u);
}

TEST(PipelineTest, TwentySynsTriggerExactlyOneFloodAlert) {
    PipelineHarness harness(kRules);

    for (uint32_t i = 0; i < 19; ++i)
        harness.send(tcp_frame(kClient + i, kServer, 8080, TCP_SYN));
    EXPECT_EQ(harness.count(5002), 0u);

    harness.send(tcp_frame(kClient + 19, kServer, 8080, TCP_SYN));
    EXPECT_EQ(harness.count(5002), 1u);

    // The flood goes on: still one alert for the window.
    for (uint32_t i = 20; i < 60; ++i)
        harness.send(tcp_frame(kClient + i, kServer, 8080, TCP_SYN));
    EXPECT_EQ(harness.count(5002), 1u);
    EXPECT_EQ(harness.alerts().size(), 1u);

    // After the window it alerts again.
    harness.advance(std::chrono::seconds(61));
    for (uint32_t i = 0; i < 20; ++i)
        harness.send(tcp_frame(kClient + i, kServer, 8080, TCP_SYN));
    EXPECT_EQ(harness.count(5002), 2u);
}

TEST(PipelineTest, FloodThresholdFollowsTheRule) {
    PipelineHarness harness(
        {R"(alert tcp any any -> any any (flags:S; threshold:5,10; msg:"flood"; sid:2001;))"});

    for (uint32_t i = 0; i < 5; ++i)
        harness.send(tcp_frame(kClient + i, kServer, 8080, TCP_SYN));
    EXPECT_EQ(harness.count(5002), 1u);
}

TEST(PipelineTest, NonFirstFragmentDoesNotTriggerAPortRule) {
    PipelineHarness harness(kRules);

    // Bytes in the fragment's body happen to look like a SYN to port 22; a non-first fragment
    // has no TCP header, so none of that may be read.
    FrameOptions opts;
    opts.flags_fragment = 185;  // fragment offset 185 (x 8 bytes), no more-fragments flag
    harness.send(ipv4_frame(6, kClient, kServer, tcp_segment(40000, 22, TCP_SYN), opts));

    EXPECT_TRUE(harness.alerts().empty());
    EXPECT_EQ(harness.stats().total_packets(), 1u);
    EXPECT_EQ(harness.stats().tcp_count(), 0u);
}

TEST(PipelineTest, FirstFragmentStillCarriesItsTransportHeader) {
    PipelineHarness harness(kRules);

    FrameOptions opts;
    opts.flags_fragment = 0x2000;  // more-fragments flag, offset 0
    harness.send(ipv4_frame(6, kClient, kServer, tcp_segment(40000, 22, TCP_SYN), opts));

    EXPECT_EQ(harness.count(1001), 1u);
}

TEST(PipelineTest, EthernetPaddingIsNotPayload) {
    const std::vector<std::string> rules = {
        R"(alert tcp any any -> any 80 (content:"AAAA"; msg:"AAAA in payload"; sid:1500;))"};

    // A bare SYN is 54 bytes, which Ethernet pads to 60. The padding here is 'A's; a content
    // rule must not see it.
    {
        PipelineHarness harness(rules);
        FrameOptions opts;
        opts.min_frame_size = 60;
        opts.pad_byte = 'A';
        auto frame = tcp_frame(kClient, kServer, 80, TCP_SYN, "", opts);
        ASSERT_EQ(frame.size(), 60u);
        harness.send(frame);
        EXPECT_TRUE(harness.alerts().empty());
    }

    // The same bytes inside the IP total length are payload and do match.
    {
        PipelineHarness harness(rules);
        harness.send(tcp_frame(kClient, kServer, 80, TCP_PSH | TCP_ACK, "AAAA"));
        EXPECT_EQ(harness.count(1500), 1u);
    }
}

TEST(PipelineTest, ParsePacketTrimsPayloadToTheIpTotalLength) {
    FrameOptions opts;
    opts.min_frame_size = 80;
    opts.pad_byte = 0xFF;
    const auto frame = tcp_frame(kClient, kServer, 80, TCP_PSH | TCP_ACK, "hello", opts);

    auto pkt = parse_packet(frame.data(), static_cast<uint32_t>(frame.size()),
                            std::chrono::system_clock::now());
    ASSERT_TRUE(pkt.has_value());
    ASSERT_TRUE(pkt->tcp.has_value());
    EXPECT_EQ(pkt->payload_length, 5u);
    EXPECT_EQ(std::string(reinterpret_cast<const char*>(pkt->payload), pkt->payload_length),
              "hello");
}

TEST(PipelineTest, ZeroIpTotalLengthMeansUseTheCapturedLength) {
    FrameOptions opts;
    opts.zero_total_length = true;
    const auto frame = tcp_frame(kClient, kServer, 80, TCP_PSH | TCP_ACK, "hello", opts);

    auto pkt = parse_packet(frame.data(), static_cast<uint32_t>(frame.size()),
                            std::chrono::system_clock::now());
    ASSERT_TRUE(pkt.has_value());
    ASSERT_TRUE(pkt->tcp.has_value());
    EXPECT_EQ(pkt->payload_length, 5u);
}

TEST(PipelineTest, IpTotalLengthShorterThanTheHeaderInvalidatesTheIpLayer) {
    auto frame = tcp_frame(kClient, kServer, 22, TCP_SYN);
    frame[16] = 0;
    frame[17] = 10;  // total length 10 < 20-byte header

    PipelineHarness harness(kRules);
    harness.send(frame);
    EXPECT_TRUE(harness.alerts().empty());

    auto pkt = parse_packet(frame.data(), static_cast<uint32_t>(frame.size()),
                            std::chrono::system_clock::now());
    ASSERT_TRUE(pkt.has_value());
    EXPECT_FALSE(pkt->ipv4.has_value());
}

TEST(PipelineTest, TcpDataOffsetBelowFiveIsRejected) {
    PipelineHarness harness(kRules);

    harness.send(ipv4_frame(6, kClient, kServer, tcp_segment(40000, 22, TCP_SYN, "", 0)));
    harness.send(ipv4_frame(6, kClient, kServer, tcp_segment(40000, 22, TCP_SYN, "", 4)));

    EXPECT_TRUE(harness.alerts().empty());
    EXPECT_EQ(harness.stats().tcp_count(), 0u);
}

TEST(PipelineTest, TcpDataOffsetBeyondTheSegmentIsRejected) {
    PipelineHarness harness(kRules);

    // 20-byte segment that claims a 60-byte header.
    harness.send(ipv4_frame(6, kClient, kServer, tcp_segment(40000, 22, TCP_SYN, "", 15)));

    EXPECT_TRUE(harness.alerts().empty());
    EXPECT_EQ(harness.stats().tcp_count(), 0u);
}

TEST(PipelineTest, TcpOptionsPushThePayloadStartForward) {
    // Data offset 6: four option bytes sit between the fixed header and the payload.
    auto segment = tcp_segment(40000, 80, TCP_PSH | TCP_ACK, "", 6);
    segment.insert(segment.end(), {1, 1, 1, 0});
    const std::string body = "GET /admin";
    segment.insert(segment.end(), body.begin(), body.end());
    const auto frame = ipv4_frame(6, kClient, kServer, segment);

    auto pkt = parse_packet(frame.data(), static_cast<uint32_t>(frame.size()),
                            std::chrono::system_clock::now());
    ASSERT_TRUE(pkt.has_value());
    ASSERT_TRUE(pkt->tcp.has_value());
    EXPECT_EQ(std::string(reinterpret_cast<const char*>(pkt->payload), pkt->payload_length), body);
}

TEST(PipelineTest, TruncatedFramesAreIgnoredWithoutReadingPastTheBuffer) {
    PipelineHarness harness(kRules);
    const auto full = tcp_frame(kClient, kServer, 22, TCP_SYN);

    // Every prefix of a valid SYN: shorter than Ethernet, mid-IP header, mid-TCP header. None
    // may crash (run under ASan to check reads) and none but the full frame may alert.
    for (size_t cut = 0; cut < full.size(); ++cut) {
        std::vector<uint8_t> prefix(full.begin(), full.begin() + cut);
        harness.send(prefix);
    }
    EXPECT_TRUE(harness.alerts().empty());

    harness.send(full);
    EXPECT_EQ(harness.count(1001), 1u);
}

TEST(PipelineTest, LongDnsQueriesRaiseATunnellingAlert) {
    PipelineHarness harness(kRules);
    const std::string name = std::string(30, 'a') + "." + std::string(30, 'b') + ".example.com";
    ASSERT_GT(name.size(), 50u);

    for (int i = 0; i < 19; ++i)
        harness.send(dns_frame(kClient, kResolver, name, false, false));
    EXPECT_EQ(harness.count(5003), 0u);

    harness.send(dns_frame(kClient, kResolver, name, false, false));
    EXPECT_EQ(harness.count(5003), 1u);
    EXPECT_EQ(harness.stats().dns_count(), 20u);
}

TEST(PipelineTest, DnsResponsesDoNotRaiseATunnellingAlert) {
    PipelineHarness harness(kRules);
    const std::string name = std::string(30, 'a') + "." + std::string(30, 'b') + ".example.com";

    for (int i = 0; i < 60; ++i)
        harness.send(dns_frame(kResolver, kClient, name, true, true));

    EXPECT_TRUE(harness.alerts().empty());
    EXPECT_EQ(harness.stats().dns_count(), 60u);
}

TEST(PipelineTest, QueriesThatSetTheResponseBitAreStillTunnelling) {
    PipelineHarness harness(kRules);
    const std::string name = std::string(30, 'a') + "." + std::string(30, 'b') + ".example.com";

    // Sent to port 53 but with QR=1: the sender chose that bit, the transport says query.
    for (int i = 0; i < 20; ++i)
        harness.send(dns_frame(kClient, kResolver, name, true, false));

    EXPECT_EQ(harness.count(5003), 1u);
}

TEST(PipelineTest, ShortDnsQueriesAreNotTunnelling) {
    PipelineHarness harness(kRules);

    for (int i = 0; i < 60; ++i)
        harness.send(dns_frame(kClient, kResolver, "example.com", false, false));

    EXPECT_TRUE(harness.alerts().empty());
}

TEST(PipelineTest, UdpPaddingIsNotDnsData) {
    // A UDP datagram whose length field covers only the DNS header: the question bytes that
    // follow in the frame are padding and must not be parsed as a name.
    auto msg =
        dns_message(std::string(30, 'a') + "." + std::string(30, 'b') + ".example.com", false);
    std::vector<uint8_t> dgram;
    put16(dgram, 40000);
    put16(dgram, 53);
    put16(dgram, 8 + 12);  // header only
    put16(dgram, 0);
    dgram.insert(dgram.end(), msg.begin(), msg.end());
    const auto frame = ipv4_frame(17, kClient, kResolver, dgram);

    auto pkt = parse_packet(frame.data(), static_cast<uint32_t>(frame.size()),
                            std::chrono::system_clock::now());
    ASSERT_TRUE(pkt.has_value());
    ASSERT_TRUE(pkt->udp.has_value());
    EXPECT_EQ(pkt->payload_length, 12u);
    // The twelve bytes that remain are a header with no question section behind it.
    EXPECT_FALSE(pkt->dns.has_value());
}

TEST(PipelineTest, ArpFramesAreParsedAndCounted) {
    std::vector<uint8_t> frame(12, 0xBB);
    put16(frame, 0x0806);
    put16(frame, 1);       // hardware type: Ethernet
    put16(frame, 0x0800);  // protocol: IPv4
    frame.push_back(6);
    frame.push_back(4);
    put16(frame, 1);  // request
    frame.insert(frame.end(), 6, 0xAA);
    put32(frame, kClient);
    frame.insert(frame.end(), 6, 0x00);
    put32(frame, kServer);

    PipelineHarness harness(kRules);
    harness.send(frame);

    EXPECT_EQ(harness.stats().arp_count(), 1u);
    EXPECT_TRUE(harness.alerts().empty());
}

TEST(PipelineTest, VerboseModePrintsOneLinePerPacket) {
    PipelineHarness harness(kRules);

    testing::internal::CaptureStdout();
    harness.send(tcp_frame(kClient, kServer, 8080, TCP_SYN), true);
    const std::string out = testing::internal::GetCapturedStdout();

    EXPECT_NE(out.find("10.0.0.1:40000 -> 192.168.1.100:8080"), std::string::npos) << out;
}
