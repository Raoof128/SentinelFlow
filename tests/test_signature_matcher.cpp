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
