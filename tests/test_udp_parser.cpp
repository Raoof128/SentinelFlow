#include <gtest/gtest.h>
#include "sentinelflow/parser/udp_parser.hpp"

using namespace sf;

TEST(UDPParserTest, ParsesValidDatagram) {
    uint8_t data[8] = {};
    // src port = 12345
    data[0] = 0x30; data[1] = 0x39;
    // dst port = 53
    data[2] = 0x00; data[3] = 0x35;
    // length = 30
    data[4] = 0x00; data[5] = 0x1E;

    UDPHeader header;
    ASSERT_TRUE(parse_udp(data, sizeof(data), header));
    EXPECT_EQ(header.src_port, 12345);
    EXPECT_EQ(header.dst_port, 53);
    EXPECT_EQ(header.length, 30);
}

TEST(UDPParserTest, RejectsTooShort) {
    uint8_t data[] = {0x00, 0x35, 0x00};
    UDPHeader header;
    ASSERT_FALSE(parse_udp(data, sizeof(data), header));
}
