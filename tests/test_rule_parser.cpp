#include <cstdio>
#include <fstream>
#include <string>

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

namespace {

std::optional<Rule> parse(const std::string& line, std::string* error = nullptr) {
    return RuleParser::parse_line(line, error);
}

}  // namespace

TEST(RuleParserTest, ParsesCidrAddresses) {
    auto rule = parse(
        R"(alert tcp 10.0.0.0/8 any -> 192.168.1.0/24 22 (msg:"Internal to server net"; sid:1;))");
    ASSERT_TRUE(rule.has_value());
    EXPECT_EQ(rule->src_ip, "10.0.0.0/8");
    EXPECT_EQ(rule->dst_ip, "192.168.1.0/24");
}

TEST(RuleParserTest, RejectsNegativeSid) {
    // std::stoul("-5") wraps to 18446744073709551611 instead of failing.
    std::string error;
    EXPECT_FALSE(parse(R"(alert tcp any any -> any 22 (msg:"x"; sid:-5;))", &error).has_value());
    EXPECT_NE(error.find("sid"), std::string::npos);
}

TEST(RuleParserTest, RejectsSidWithTrailingGarbage) {
    EXPECT_FALSE(parse(R"(alert tcp any any -> any 22 (msg:"x"; sid:12abc;))").has_value());
}

TEST(RuleParserTest, RejectsSidThatOverflows) {
    EXPECT_FALSE(parse(R"(alert tcp any any -> any 22 (msg:"x"; sid:99999999999;))").has_value());
}

TEST(RuleParserTest, RejectsMalformedAddresses) {
    EXPECT_FALSE(parse(R"(alert tcp 10.0.0.0/33 any -> any 22 (sid:1;))").has_value());
    EXPECT_FALSE(parse(R"(alert tcp any any -> 999.1.1.1 22 (sid:1;))").has_value());
    EXPECT_FALSE(parse(R"(alert tcp example.com any -> any 22 (sid:1;))").has_value());
}

TEST(RuleParserTest, RejectsMalformedPorts) {
    EXPECT_FALSE(parse(R"(alert tcp any any -> any 70000 (sid:1;))").has_value());
    EXPECT_FALSE(parse(R"(alert tcp any any -> any 22abc (sid:1;))").has_value());
    EXPECT_FALSE(parse(R"(alert tcp any any -> any 80:90 (sid:1;))").has_value());
}

TEST(RuleParserTest, RejectsUnknownProtocol) {
    EXPECT_FALSE(parse(R"(alert tpc any any -> any 22 (sid:1;))").has_value());
}

TEST(RuleParserTest, RejectsBadThreshold) {
    EXPECT_FALSE(parse(R"(alert tcp any any -> any any (threshold:20; sid:1;))").has_value());
    EXPECT_FALSE(parse(R"(alert tcp any any -> any any (threshold:0,60; sid:1;))").has_value());
    EXPECT_FALSE(parse(R"(alert tcp any any -> any any (threshold:20,0; sid:1;))").has_value());
    EXPECT_FALSE(parse(R"(alert tcp any any -> any any (threshold:-1,60; sid:1;))").has_value());
    EXPECT_FALSE(parse(R"(alert tcp any any -> any any (threshold:a,b; sid:1;))").has_value());
}

TEST(RuleParserTest, RejectsBadDnsQueryLen) {
    EXPECT_FALSE(parse(R"(alert udp any any -> any 53 (dns_query_len:50; sid:1;))").has_value());
    EXPECT_FALSE(parse(R"(alert udp any any -> any 53 (dns_query_len:>x; sid:1;))").has_value());
}

TEST(RuleParserTest, RejectsUnknownFlagLetters) {
    EXPECT_FALSE(parse(R"(alert tcp any any -> any any (flags:SX; sid:1;))").has_value());
}

TEST(RuleParserTest, RejectsUnsupportedOption) {
    // Dropping an option silently would make the rule match more than its author intended.
    std::string error;
    EXPECT_FALSE(parse(R"(alert tcp any any -> any 22 (sid:1; nocase;))", &error).has_value());
    EXPECT_NE(error.find("nocase"), std::string::npos);
}

TEST(RuleParserTest, ContentMayContainSemicolon) {
    auto rule = parse(R"(alert tcp any any -> any 80 (content:"a;b"; msg:"semi"; sid:7;))");
    ASSERT_TRUE(rule.has_value());
    ASSERT_TRUE(rule->content.has_value());
    EXPECT_EQ(*rule->content, "a;b");
    EXPECT_EQ(rule->sid, 7u);
}

TEST(RuleParserTest, LoadFromFileCountsRejectedLines) {
    const std::string path = testing::TempDir() + "sf_rules_count.rules";
    {
        std::ofstream out(path);
        out << "# comment\n"
            << "\n"
            << R"(alert tcp any any -> any 22 (msg:"ok"; sid:1;))"
            << "\n"
            << "this is not a rule\n"
            << R"(alert tcp any any -> any 23 (msg:"bad sid"; sid:-1;))"
            << "\n"
            << R"(alert tcp any any -> any 24 (msg:"ok too"; sid:2;))"
            << "\n";
    }

    RuleLoadStats stats;
    testing::internal::CaptureStderr();
    auto rules = RuleParser::load_from_file(path, &stats);
    const std::string log = testing::internal::GetCapturedStderr();

    EXPECT_EQ(rules.size(), 2u);
    EXPECT_EQ(stats.loaded, 2u);
    EXPECT_EQ(stats.rejected, 2u);
    // The warning names the file line so the author can find it.
    EXPECT_NE(log.find(":4:"), std::string::npos) << log;
    EXPECT_NE(log.find(":5:"), std::string::npos) << log;
    EXPECT_NE(log.find("2 of 4"), std::string::npos) << log;
    std::remove(path.c_str());
}

TEST(RuleParserTest, AllowsATrailingComment) {
    EXPECT_TRUE(
        parse(R"(alert tcp any any -> any 22 (msg:"x"; sid:1;)  # why this exists)").has_value());
}

TEST(RuleParserTest, RejectsTextAroundTheOptionList) {
    EXPECT_FALSE(parse(R"(alert tcp any any -> any 22 extra (msg:"x"; sid:1;))").has_value());
    EXPECT_FALSE(parse(R"(alert tcp any any -> any 22 (msg:"x"; sid:1;) extra)").has_value());
    EXPECT_FALSE(parse(R"(alert tcp any any -> any 22)").has_value());
}

TEST(RuleParserTest, RejectsUnquotedMessage) {
    EXPECT_FALSE(parse(R"(alert tcp any any -> any 22 (msg:hello; sid:1;))").has_value());
}

TEST(RuleParserTest, DocumentedExamplesParse) {
    // The example rules in docs/rules_format.md and the README.
    for (
        const char* line : {
            R"(alert tcp any any -> any 22 (msg:"SSH connection attempt"; sid:1001;))",
            R"(alert tcp any any -> any any (flags:S; threshold:100,10; msg:"Possible SYN flood"; sid:2001;))",
            R"(alert udp any any -> any 53 (dns_query_len:>50; msg:"Possible DNS tunnelling"; sid:3001;))",
            R"(alert tcp 10.0.0.0/8 any -> 192.168.1.0/24 3306 (msg:"Internal MySQL access"; sid:1007;))",
            R"(alert tcp any any -> any 80 (content:"GET /admin"; msg:"Admin page access"; sid:4001;))",
            R"(alert tcp any any -> any any (flags:SAFPRU; msg:"Xmas tree scan detected"; sid:4002;))",
        }) {
        std::string error;
        EXPECT_TRUE(parse(line, &error).has_value()) << line << ": " << error;
    }
}
