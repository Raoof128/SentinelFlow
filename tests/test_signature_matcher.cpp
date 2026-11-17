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
