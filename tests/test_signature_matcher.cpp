#include <gtest/gtest.h>

#include "sentinelflow/detection/signature_matcher.hpp"

using namespace sf;

TEST(SignatureMatcherTest, MatchesSSHRule) {
    std::vector<Rule> rules;
    Rule r;
    r.sid = 1001;
    r.action = "alert";
    r.protocol = "tcp";
    r.src_ip = "any";
    r.src_port = "any";
    r.dst_ip = "any";
    r.dst_port = "22";
    r.message = "SSH connection attempt";
    rules.push_back(r);

    SignatureMatcher matcher(rules);

    ParsedPacket pkt;
    pkt.timestamp = std::chrono::system_clock::now();
    pkt.ipv4 = IPv4Header{};
    pkt.ipv4->src_ip = 0xC0A80101;
    pkt.ipv4->dst_ip = 0xC0A80102;
    pkt.tcp = TCPHeader{};
    pkt.tcp->src_port = 54321;
    pkt.tcp->dst_port = 22;
    pkt.tcp->flags = TCP_SYN;

    auto alerts = matcher.check(pkt);
    ASSERT_EQ(alerts.size(), 1);
    EXPECT_EQ(alerts[0].sid, 1001);
}

TEST(SignatureMatcherTest, NoMatchWrongPort) {
    std::vector<Rule> rules;
    Rule r;
    r.sid = 1001;
    r.action = "alert";
    r.protocol = "tcp";
    r.src_ip = "any";
    r.src_port = "any";
    r.dst_ip = "any";
    r.dst_port = "22";
    r.message = "SSH";
    rules.push_back(r);

    SignatureMatcher matcher(rules);

    ParsedPacket pkt;
    pkt.timestamp = std::chrono::system_clock::now();
    pkt.ipv4 = IPv4Header{};
    pkt.tcp = TCPHeader{};
    pkt.tcp->dst_port = 80;

    auto alerts = matcher.check(pkt);
    EXPECT_TRUE(alerts.empty());
}

namespace {

Rule make_content_rule() {
    Rule r;
    r.sid = 1010;
    r.action = "alert";
    r.protocol = "tcp";
    r.src_ip = "any";
    r.src_port = "any";
    r.dst_ip = "any";
    r.dst_port = "80";
    r.content = "GET /admin";
    r.message = "Admin page request";
    return r;
}

ParsedPacket make_http_packet() {
    ParsedPacket pkt;
    pkt.timestamp = std::chrono::system_clock::now();
    pkt.ipv4 = IPv4Header{};
    pkt.ipv4->src_ip = 0xC0A80101;
    pkt.ipv4->dst_ip = 0xC0A80102;
    pkt.tcp = TCPHeader{};
    pkt.tcp->src_port = 54321;
    pkt.tcp->dst_port = 80;
    pkt.tcp->flags = TCP_SYN;
    return pkt;
}

}  // namespace

TEST(SignatureMatcherTest, ContentRuleDoesNotMatchPacketWithoutPayload) {
    SignatureMatcher matcher({make_content_rule()});
    ParsedPacket pkt = make_http_packet();  // a bare SYN: no payload

    EXPECT_TRUE(matcher.check(pkt).empty());
}

TEST(SignatureMatcherTest, ContentRuleMatchesPayloadContainingTheString) {
    SignatureMatcher matcher({make_content_rule()});
    ParsedPacket pkt = make_http_packet();
    const std::string body = "GET /admin HTTP/1.1\r\n";
    pkt.payload = reinterpret_cast<const uint8_t*>(body.data());
    pkt.payload_length = static_cast<uint32_t>(body.size());

    ASSERT_EQ(matcher.check(pkt).size(), 1);
}

TEST(SignatureMatcherTest, ContentRuleDoesNotMatchOtherPayload) {
    SignatureMatcher matcher({make_content_rule()});
    ParsedPacket pkt = make_http_packet();
    const std::string body = "GET /index.html HTTP/1.1\r\n";
    pkt.payload = reinterpret_cast<const uint8_t*>(body.data());
    pkt.payload_length = static_cast<uint32_t>(body.size());

    EXPECT_TRUE(matcher.check(pkt).empty());
}

namespace {

Rule make_rule(const std::string& protocol, const std::string& src_ip, const std::string& dst_ip,
               const std::string& dst_port) {
    Rule r;
    r.sid = 2000;
    r.action = "alert";
    r.protocol = protocol;
    r.src_ip = src_ip;
    r.src_port = "any";
    r.dst_ip = dst_ip;
    r.dst_port = dst_port;
    r.message = "test rule";
    return r;
}

ParsedPacket make_tcp_packet(IPv4Address src, IPv4Address dst, uint16_t dst_port) {
    ParsedPacket pkt;
    pkt.timestamp = std::chrono::system_clock::now();
    pkt.ipv4 = IPv4Header{};
    pkt.ipv4->src_ip = src;
    pkt.ipv4->dst_ip = dst;
    pkt.tcp = TCPHeader{};
    pkt.tcp->dst_port = dst_port;
    pkt.tcp->flags = TCP_SYN;
    return pkt;
}

}  // namespace

TEST(SignatureMatcherTest, CidrSourceRuleMatchesInsideTheNetwork) {
    SignatureMatcher matcher({make_rule("tcp", "10.0.0.0/8", "any", "22")});

    EXPECT_EQ(matcher.check(make_tcp_packet(0x0A010203, 0xC0A80102, 22)).size(), 1u);
    EXPECT_TRUE(matcher.check(make_tcp_packet(0xC0A80101, 0xC0A80102, 22)).empty());
}

TEST(SignatureMatcherTest, CidrDestinationRuleMatchesInsideTheNetwork) {
    SignatureMatcher matcher({make_rule("tcp", "any", "192.168.1.0/24", "22")});

    EXPECT_EQ(matcher.check(make_tcp_packet(0x0A000001, 0xC0A80164, 22)).size(), 1u);
    EXPECT_TRUE(matcher.check(make_tcp_packet(0x0A000001, 0xC0A80264, 22)).empty());
}

TEST(SignatureMatcherTest, PortRuleDoesNotMatchPacketWithoutTransportHeader) {
    // A rule for any protocol and port 22 must not fire on a packet that has no port (a
    // non-first fragment, an ICMP message): the port check used to be skipped.
    SignatureMatcher matcher({make_rule("any", "any", "any", "22")});

    ParsedPacket fragment;
    fragment.timestamp = std::chrono::system_clock::now();
    fragment.ipv4 = IPv4Header{};
    EXPECT_TRUE(matcher.check(fragment).empty());

    ParsedPacket icmp = fragment;
    icmp.icmp = ICMPHeader{};
    EXPECT_TRUE(matcher.check(icmp).empty());
}

TEST(SignatureMatcherTest, AddressRuleDoesNotMatchPacketWithoutIpv4) {
    SignatureMatcher matcher({make_rule("any", "10.0.0.0/8", "any", "any")});

    ParsedPacket arp;
    arp.timestamp = std::chrono::system_clock::now();
    arp.arp = ARPHeader{};
    EXPECT_TRUE(matcher.check(arp).empty());
}

TEST(SignatureMatcherTest, FlagsRuleDoesNotMatchUdp) {
    Rule r = make_rule("any", "any", "any", "any");
    r.tcp_flags = TCP_SYN;
    SignatureMatcher matcher({r});

    ParsedPacket udp;
    udp.timestamp = std::chrono::system_clock::now();
    udp.ipv4 = IPv4Header{};
    udp.udp = UDPHeader{};
    EXPECT_TRUE(matcher.check(udp).empty());
}
