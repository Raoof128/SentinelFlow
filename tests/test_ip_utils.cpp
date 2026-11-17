#include <gtest/gtest.h>

#include "sentinelflow/utils/ip_utils.hpp"

using namespace sf;

TEST(IpUtilsTest, AnyMatchesEverything) {
    EXPECT_TRUE(ip_matches(0, "any"));
    EXPECT_TRUE(ip_matches(0xFFFFFFFF, "any"));
}

TEST(IpUtilsTest, ExactAddressMatch) {
    EXPECT_TRUE(ip_matches(0xC0A80164, "192.168.1.100"));
    EXPECT_FALSE(ip_matches(0xC0A80165, "192.168.1.100"));
}

TEST(IpUtilsTest, CidrMatchesAddressesInsideTheNetwork) {
    EXPECT_TRUE(ip_matches(0x0A000001, "10.0.0.0/8"));
    EXPECT_TRUE(ip_matches(0x0AFFFFFF, "10.0.0.0/8"));
    EXPECT_FALSE(ip_matches(0x0B000001, "10.0.0.0/8"));

    EXPECT_TRUE(ip_matches(0xC0A80164, "192.168.1.0/24"));
    EXPECT_FALSE(ip_matches(0xC0A80264, "192.168.1.0/24"));

    EXPECT_TRUE(ip_matches(0xC0A80164, "192.168.1.96/27"));    // .96 - .127
    EXPECT_FALSE(ip_matches(0xC0A80160, "192.168.1.128/27"));  // .96 is outside .128/27
}

TEST(IpUtilsTest, CidrPrefixBoundaries) {
    EXPECT_TRUE(ip_matches(0x01020304, "0.0.0.0/0"));  // /0 matches everything
    EXPECT_TRUE(ip_matches(0xC0A80164, "192.168.1.100/32"));
    EXPECT_FALSE(ip_matches(0xC0A80165, "192.168.1.100/32"));
}

TEST(IpUtilsTest, CidrIgnoresHostBitsInThePattern) {
    EXPECT_TRUE(ip_matches(0x0A010203, "10.1.2.3/8"));
    EXPECT_TRUE(ip_matches(0x0A630000, "10.1.2.3/8"));
}

TEST(IpUtilsTest, MalformedPatternsNeverMatch) {
    // The old string_to_ip returned 0 for anything it could not parse, so a bad pattern matched
    // the address 0.0.0.0 and a CIDR pattern matched nothing.
    EXPECT_FALSE(ip_matches(0, "garbage"));
    EXPECT_FALSE(ip_matches(0, "10.0.0.0/33"));
    EXPECT_FALSE(ip_matches(0x0A000001, "10.0.0.0/33"));
    EXPECT_FALSE(ip_matches(0x0A000001, "10.0.0.0/"));
    EXPECT_FALSE(ip_matches(0x0A000001, "10.0.0.0/-1"));
    EXPECT_FALSE(ip_matches(0x0A000001, "10.0.0.0/8x"));
    EXPECT_FALSE(ip_matches(0x0A000001, "10.0.0/8"));
    EXPECT_FALSE(ip_matches(0x0A000001, ""));
}

TEST(IpUtilsTest, ValidatesIpPatterns) {
    EXPECT_TRUE(is_valid_ip_pattern("any"));
    EXPECT_TRUE(is_valid_ip_pattern("10.0.0.1"));
    EXPECT_TRUE(is_valid_ip_pattern("10.0.0.0/8"));
    EXPECT_TRUE(is_valid_ip_pattern("0.0.0.0/0"));
    EXPECT_FALSE(is_valid_ip_pattern("10.0.0.0/33"));
    EXPECT_FALSE(is_valid_ip_pattern("10.0.0.256"));
    EXPECT_FALSE(is_valid_ip_pattern("example.com"));
    EXPECT_FALSE(is_valid_ip_pattern(""));
}

TEST(IpUtilsTest, PortMatching) {
    EXPECT_TRUE(port_matches(22, "any"));
    EXPECT_TRUE(port_matches(22, "22"));
    EXPECT_FALSE(port_matches(23, "22"));
    EXPECT_TRUE(port_matches(65535, "65535"));
    EXPECT_FALSE(port_matches(1, "65536"));
}

TEST(IpUtilsTest, PortPatternsMustBeStrictlyNumeric) {
    // std::stoi accepted "22abc", " 22" and "+22".
    EXPECT_FALSE(port_matches(22, "22abc"));
    EXPECT_FALSE(port_matches(22, " 22"));
    EXPECT_FALSE(port_matches(22, "+22"));
    EXPECT_FALSE(port_matches(22, ""));
    EXPECT_TRUE(is_valid_port_pattern("any"));
    EXPECT_TRUE(is_valid_port_pattern("0"));
    EXPECT_FALSE(is_valid_port_pattern("65536"));
    EXPECT_FALSE(is_valid_port_pattern("-1"));
    EXPECT_FALSE(is_valid_port_pattern("80:90"));
}
