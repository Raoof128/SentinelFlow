#include <gtest/gtest.h>
#include "sentinelflow/parser/ethernet_parser.hpp"

using namespace sf;

TEST(EthernetParserTest, ParsesValidFrame) {
    uint8_t data[] = {
        // Dst MAC: AA:BB:CC:DD:EE:FF
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        // Src MAC: 11:22:33:44:55:66
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        // EtherType: 0x0800 (IPv4)
        0x08, 0x00
    };

    EthernetHeader header;
    ASSERT_TRUE(parse_ethernet(data, sizeof(data), header));
    EXPECT_EQ(header.ether_type, 0x0800);
    EXPECT_EQ(header.dst_mac[0], 0xAA);
    EXPECT_EQ(header.src_mac[0], 0x11);
}

TEST(EthernetParserTest, RejectsTooShort) {
    uint8_t data[] = {0xAA, 0xBB, 0xCC};
    EthernetHeader header;
    ASSERT_FALSE(parse_ethernet(data, sizeof(data), header));
}

TEST(EthernetParserTest, ParsesARPEtherType) {
    uint8_t data[14] = {};
    data[12] = 0x08;
    data[13] = 0x06; // ARP
    EthernetHeader header;
    ASSERT_TRUE(parse_ethernet(data, sizeof(data), header));
    EXPECT_EQ(header.ether_type, 0x0806);
}
