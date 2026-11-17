#include <gtest/gtest.h>

#include "sentinelflow/parser/ip_parser.hpp"

using namespace sf;

TEST(IPv4ParserTest, ParsesValidPacket) {
    uint8_t data[] = {0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06,
                      0xb1, 0xe6, 0xac, 0x10, 0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c};

    IPv4Header header;
    ASSERT_TRUE(parse_ipv4(data, sizeof(data), header));
    EXPECT_EQ(header.version, 4);
    EXPECT_EQ(header.ihl, 5);
    EXPECT_EQ(header.ttl, 64);
    EXPECT_EQ(header.protocol, 6);
}

TEST(IPv4ParserTest, RejectsTooShort) {
    uint8_t data[] = {0x45, 0x00, 0x00};
    IPv4Header header;
    ASSERT_FALSE(parse_ipv4(data, sizeof(data), header));
}

TEST(IPv4ParserTest, RejectsWrongVersion) {
    uint8_t data[20] = {};
    data[0] = 0x65;  // Version 6
    IPv4Header header;
    ASSERT_FALSE(parse_ipv4(data, sizeof(data), header));
}

TEST(IPv4ParserTest, RejectsShortIHL) {
    uint8_t data[20] = {};
    data[0] = 0x43;  // Version 4, IHL 3 (invalid, min is 5)
    IPv4Header header;
    ASSERT_FALSE(parse_ipv4(data, sizeof(data), header));
}

TEST(IPv4ParserTest, RejectsHeaderLongerThanBuffer) {
    uint8_t data[20] = {};
    data[0] = 0x46;  // Version 4, IHL 6: the header claims 24 bytes but only 20 are present
    IPv4Header header;
    ASSERT_FALSE(parse_ipv4(data, sizeof(data), header));
}
