#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "sentinelflow/detection/detection_engine.hpp"

using namespace sf;

namespace {

std::string write_rules(const std::string& name, const std::string& body) {
    const std::string path = testing::TempDir() + name;
    std::ofstream out(path);
    out << body;
    return path;
}

ParsedPacket syn(IPv4Address src, IPv4Address dst, uint16_t port,
                 std::chrono::system_clock::time_point ts) {
    ParsedPacket pkt;
    pkt.timestamp = ts;
    pkt.ipv4 = IPv4Header{};
    pkt.ipv4->src_ip = src;
    pkt.ipv4->dst_ip = dst;
    pkt.tcp = TCPHeader{};
    pkt.tcp->src_port = 40000;
    pkt.tcp->dst_port = port;
    pkt.tcp->flags = TCP_SYN;
    return pkt;
}

ParsedPacket dns_query(IPv4Address src, const std::string& name,
                       std::chrono::system_clock::time_point ts) {
    ParsedPacket pkt;
    pkt.timestamp = ts;
    pkt.ipv4 = IPv4Header{};
    pkt.ipv4->src_ip = src;
    pkt.ipv4->dst_ip = 0x08080808;
    pkt.udp = UDPHeader{};
    pkt.udp->dst_port = 53;
    pkt.dns = DNSHeader{};
    pkt.dns->query_name = name;
    return pkt;
}

int count_sid(const std::vector<Alert>& alerts, uint32_t sid) {
    int n = 0;
    for (const auto& a : alerts)
        if (a.sid == sid)
            ++n;
    return n;
}

// Send `count` SYNs from distinct sources to one target port and return the alerts.
std::vector<Alert> flood(DetectionEngine& engine, int count) {
    std::vector<Alert> all;
    const auto t = std::chrono::system_clock::now();
    for (int i = 0; i < count; ++i) {
        auto alerts = engine.analyze(syn(0x0A000001 + i, 0xC0A80101, 8080, t));
        all.insert(all.end(), alerts.begin(), alerts.end());
    }
    return all;
}

}  // namespace

TEST(DetectionEngineRulesTest, SynFloodThresholdComesFromTheRulesFile) {
    const std::string path = write_rules(
        "sf_engine_syn.rules",
        R"(alert tcp any any -> any any (flags:S; threshold:5,10; msg:"flood"; sid:2001;))"
        "\n");
    DetectionEngine engine;
    engine.load_rules(path);
    std::remove(path.c_str());

    // The built-in default is 100 SYNs in 10 s, so five would not alert without the rule.
    EXPECT_EQ(count_sid(flood(engine, 5), 5002), 1);
}

TEST(DetectionEngineRulesTest, SynFloodWindowComesFromTheRulesFile) {
    const std::string path = write_rules(
        "sf_engine_syn_window.rules",
        R"(alert tcp any any -> any any (flags:S; threshold:3,2; msg:"flood"; sid:2001;))"
        "\n");
    DetectionEngine engine;
    engine.load_rules(path);
    std::remove(path.c_str());

    // Threshold 3 in a 2 s window: SYNs 3 s apart never accumulate, but three together do.
    const auto t = std::chrono::system_clock::now();
    EXPECT_TRUE(engine.analyze(syn(1, 0xC0A80101, 80, t)).empty());
    EXPECT_TRUE(engine.analyze(syn(2, 0xC0A80101, 80, t + std::chrono::seconds(3))).empty());
    EXPECT_TRUE(engine.analyze(syn(3, 0xC0A80101, 80, t + std::chrono::seconds(6))).empty());
    EXPECT_TRUE(engine.analyze(syn(4, 0xC0A80101, 80, t + std::chrono::seconds(7))).empty());
    EXPECT_EQ(count_sid(engine.analyze(syn(5, 0xC0A80101, 80, t + std::chrono::seconds(7))), 5002),
              1);
}

TEST(DetectionEngineRulesTest, DefaultsApplyWhenNoRuleSetsThem) {
    DetectionEngine engine;
    EXPECT_EQ(count_sid(flood(engine, 99), 5002), 0);
    EXPECT_EQ(count_sid(flood(engine, 1), 5002), 1);  // the 100th SYN in the window
}

TEST(DetectionEngineRulesTest, DnsQueryLengthComesFromTheRulesFile) {
    const std::string path =
        write_rules("sf_engine_dns.rules",
                    R"(alert udp any any -> any 53 (dns_query_len:>20; msg:"tunnel"; sid:3001;))"
                    "\n");
    DetectionEngine engine;
    engine.load_rules(path);
    std::remove(path.c_str());

    const std::string name(30, 'a');  // longer than 20, shorter than the default 50
    const auto t = std::chrono::system_clock::now();
    int alerts = 0;
    for (int i = 0; i < 20; ++i)
        alerts += count_sid(engine.analyze(dns_query(1, name, t)), 5003);
    EXPECT_EQ(alerts, 1);
}

TEST(DetectionEngineRulesTest, ShortDnsNamesStayBelowTheRuleLength) {
    const std::string path =
        write_rules("sf_engine_dns_short.rules",
                    R"(alert udp any any -> any 53 (dns_query_len:>40; msg:"tunnel"; sid:3001;))"
                    "\n");
    DetectionEngine engine;
    engine.load_rules(path);
    std::remove(path.c_str());

    const std::string name(30, 'a');  // below the rule's 40 (and the default 50)
    const auto t = std::chrono::system_clock::now();
    for (int i = 0; i < 40; ++i)
        EXPECT_EQ(count_sid(engine.analyze(dns_query(1, name, t)), 5003), 0);
}

TEST(DetectionEngineRulesTest, ThresholdRuleWithoutADetectorWarns) {
    // ICMP flood is not implemented, so its rule can only be reported, not applied.
    std::vector<Rule> rules;
    auto icmp = RuleParser::parse_line(
        R"(alert icmp any any -> any any (threshold:100,10; msg:"ICMP flood"; sid:4001;))");
    ASSERT_TRUE(icmp.has_value());
    rules.push_back(*icmp);

    DetectionEngine engine;
    auto warnings = engine.apply_rules(rules);
    ASSERT_EQ(warnings.size(), 1u);
    EXPECT_NE(warnings[0].find("4001"), std::string::npos);
    EXPECT_NE(warnings[0].find("no effect"), std::string::npos);
}

TEST(DetectionEngineRulesTest, SecondRuleForTheSameDetectorWarnsAndFirstWins) {
    std::vector<Rule> rules;
    rules.push_back(*RuleParser::parse_line(
        R"(alert tcp any any -> any any (flags:S; threshold:5,10; sid:2001;))"));
    rules.push_back(*RuleParser::parse_line(
        R"(alert tcp any any -> any any (flags:S; threshold:50,10; sid:2002;))"));

    DetectionEngine engine;
    auto warnings = engine.apply_rules(rules);
    ASSERT_EQ(warnings.size(), 1u);
    EXPECT_NE(warnings[0].find("2002"), std::string::npos);
    EXPECT_EQ(count_sid(flood(engine, 5), 5002), 1);
}

TEST(DetectionEngineRulesTest, AddressFieldsOnAStatefulRuleWarn) {
    std::vector<Rule> rules;
    rules.push_back(*RuleParser::parse_line(
        R"(alert tcp any any -> 10.0.0.0/8 any (flags:S; threshold:5,10; sid:2001;))"));

    DetectionEngine engine;
    auto warnings = engine.apply_rules(rules);
    ASSERT_EQ(warnings.size(), 1u);
    EXPECT_NE(warnings[0].find("ignored"), std::string::npos);
}

TEST(DetectionEngineRulesTest, DefaultRulesFileLoadsWithoutWarnings) {
    DetectionEngine engine;
    testing::internal::CaptureStderr();
    auto stats = engine.load_rules(SF_DEFAULT_RULES_PATH);
    const std::string log = testing::internal::GetCapturedStderr();

    EXPECT_EQ(stats.rejected, 0u) << log;
    EXPECT_GE(stats.loaded, 8u);
    EXPECT_TRUE(log.empty()) << log;
}

TEST(DetectionEngineRulesTest, DnsRuleWithThresholdSetsVolumeAndWindow) {
    std::vector<Rule> rules;
    rules.push_back(*RuleParser::parse_line(
        R"(alert udp any any -> any 53 (dns_query_len:>20; threshold:3,60; sid:3001;))"));

    DetectionEngine engine;
    EXPECT_TRUE(engine.apply_rules(rules).empty());

    const std::string name(30, 'a');
    const auto t = std::chrono::system_clock::now();
    int alerts = 0;
    for (int i = 0; i < 3; ++i)
        alerts += count_sid(engine.analyze(dns_query(1, name, t)), 5003);
    EXPECT_EQ(alerts, 1);
}

TEST(DetectionEngineRulesTest, DnsRuleOnAnotherPortWarns) {
    std::vector<Rule> rules;
    rules.push_back(*RuleParser::parse_line(
        R"(alert udp 10.0.0.0/8 any -> any 5353 (dns_query_len:>50; sid:3001;))"));

    DetectionEngine engine;
    auto warnings = engine.apply_rules(rules);
    ASSERT_EQ(warnings.size(), 1u);
    EXPECT_NE(warnings[0].find("ignored"), std::string::npos);
}

TEST(DetectionEnginePressureTest, NoAlertWhileTablesHaveRoom) {
    DetectionEngine engine;
    const auto t = std::chrono::system_clock::now();
    for (uint32_t src = 1; src <= 1000; ++src)
        EXPECT_EQ(count_sid(engine.analyze(syn(src, 2, 80, t)), kStatePressureSid), 0);
    EXPECT_EQ(engine.state_evictions().total(), 0u);
}

TEST(DetectionEnginePressureTest, FullTableRaisesOneRateLimitedAlertPerWindow) {
    DetectionEngine engine;
    const auto t = std::chrono::system_clock::now();

    // Every source probes one port of one target, so each (source, target) pair is a record; the
    // port-scan table holds kDefaultMaxTrackedSources of them and then starts dropping.
    int alerts = 0;
    Alert first;
    for (uint32_t src = 1; src <= kDefaultMaxTrackedSources + 5000; ++src) {
        for (const auto& a : engine.analyze(syn(src, 2, 80, t))) {
            if (a.sid == kStatePressureSid) {
                if (alerts == 0)
                    first = a;
                ++alerts;
            }
        }
    }
    EXPECT_EQ(alerts, 1);
    EXPECT_EQ(first.severity, AlertSeverity::MEDIUM);
    EXPECT_NE(first.message.find("State table pressure"), std::string::npos);
    EXPECT_NE(first.message.find("degraded"), std::string::npos);
    EXPECT_EQ(engine.state_evictions().port_scan, 5000u);
    EXPECT_EQ(engine.state_evictions().syn_flood, 0u);

    // Still full and still dropping, but inside the window: silent.
    for (uint32_t src = 200000; src < 200100; ++src)
        EXPECT_EQ(count_sid(engine.analyze(syn(src, 2, 80, t)), kStatePressureSid), 0);
}

TEST(DetectionEnginePressureTest, AlertsAgainOnceTheWindowHasPassedAndTheTableIsStillFull) {
    DetectionEngine engine;
    auto t = std::chrono::system_clock::now();

    auto spray = [&](uint32_t first_src, uint32_t count) {
        int alerts = 0;
        for (uint32_t src = first_src; src < first_src + count; ++src)
            alerts += count_sid(engine.analyze(syn(src, 2, 80, t)), kStatePressureSid);
        return alerts;
    };

    EXPECT_EQ(spray(1, kDefaultMaxTrackedSources + 100), 1);

    // 30 s later a full table's worth of new sources: still dropping, but inside the window.
    t += std::chrono::seconds(30);
    EXPECT_EQ(spray(1000000, kDefaultMaxTrackedSources), 0);

    // 61 s after the first alert the oldest records have expired, the rest are live and the
    // table is full again: new sources are dropped at capacity and the alert fires once more.
    t += std::chrono::seconds(31);
    EXPECT_EQ(spray(2000000, 200), 1);
}
