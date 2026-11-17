#include <gtest/gtest.h>

#include "sentinelflow/detection/rule_parser.hpp"
#include "sentinelflow/parser/packet.hpp"

using namespace sf;

TEST(RuleParserTest, ParsesBasicRule) {
    auto rule = RuleParser::parse_line(
        R"(alert tcp any any -> any 22 (msg:"SSH connection attempt"; sid:1001;))");
    ASSERT_TRUE(rule.has_value());
    EXPECT_EQ(rule->action, "alert");
    EXPECT_EQ(rule->protocol, "tcp");
    EXPECT_EQ(rule->src_ip, "any");
    EXPECT_EQ(rule->dst_port, "22");
    EXPECT_EQ(rule->message, "SSH connection attempt");
    EXPECT_EQ(rule->sid, 1001);
}

TEST(RuleParserTest, ParsesFlags) {
    auto rule =
        RuleParser::parse_line(R"(alert tcp any any -> any any (flags:S; msg:"SYN"; sid:2001;))");
    ASSERT_TRUE(rule.has_value());
    ASSERT_TRUE(rule->tcp_flags.has_value());
    EXPECT_EQ(*rule->tcp_flags, TCP_SYN);
}

TEST(RuleParserTest, ParsesThreshold) {
    auto rule = RuleParser::parse_line(
        R"(alert tcp any any -> any any (threshold:20,60; msg:"Flood"; sid:2002;))");
    ASSERT_TRUE(rule.has_value());
    ASSERT_TRUE(rule->threshold_count.has_value());
    EXPECT_EQ(*rule->threshold_count, 20);
    EXPECT_EQ(*rule->threshold_seconds, 60);
}

TEST(RuleParserTest, RejectsInvalidFormat) {
    auto rule = RuleParser::parse_line("this is not a valid rule");
    EXPECT_FALSE(rule.has_value());
}
