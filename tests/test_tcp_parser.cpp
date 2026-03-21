#include <gtest/gtest.h>
#include "sentinelflow/parser/tcp_parser.hpp"

using namespace sf;

TEST(TCPParserTest, ParsesValidSegment) {
    uint8_t data[20] = {};
    // src port = 8080
    data[0] = 0x1F; data[1] = 0x90;
    // dst port = 80
    data[2] = 0x00; data[3] = 0x50;
    // data offset = 5 (20 bytes), flags = SYN
    data[12] = 0x50;
    data[13] = 0x02;

    TCPHeader header;
    ASSERT_TRUE(parse_tcp(data, sizeof(data), header));
    EXPECT_EQ(header.src_port, 8080);
    EXPECT_EQ(header.dst_port, 80);
    EXPECT_EQ(header.flags & TCP_SYN, TCP_SYN);
    EXPECT_EQ(header.data_offset, 5);
}

TEST(TCPParserTest, RejectsTooShort) {
    uint8_t data[] = {0x1F, 0x90, 0x00, 0x50};
    TCPHeader header;
    ASSERT_FALSE(parse_tcp(data, sizeof(data), header));
}

TEST(TCPParserTest, ParsesMultipleFlags) {
    uint8_t data[20] = {};
    data[13] = TCP_SYN | TCP_ACK;
    TCPHeader header;
    ASSERT_TRUE(parse_tcp(data, sizeof(data), header));
    EXPECT_TRUE(header.flags & TCP_SYN);
    EXPECT_TRUE(header.flags & TCP_ACK);
    EXPECT_FALSE(header.flags & TCP_FIN);
}
