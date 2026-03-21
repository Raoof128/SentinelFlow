#include <gtest/gtest.h>
#include "sentinelflow/parser/dns_parser.hpp"

using namespace sf;

TEST(DNSParserTest, ParsesSimpleQuery) {
    // DNS query for "example.com"
    uint8_t data[] = {
        0x00, 0x01,  // Transaction ID
        0x01, 0x00,  // Flags: standard query
        0x00, 0x01,  // Questions: 1
        0x00, 0x00,  // Answers: 0
        0x00, 0x00,  // Authority: 0
        0x00, 0x00,  // Additional: 0
        // Query: example.com
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,        // End of name
        0x00, 0x01,  // Type: A
        0x00, 0x01   // Class: IN
    };

    DNSHeader header;
    ASSERT_TRUE(parse_dns(data, sizeof(data), header));
    EXPECT_EQ(header.transaction_id, 1);
    EXPECT_EQ(header.questions, 1);
    EXPECT_EQ(header.query_name, "example.com");
    EXPECT_EQ(header.query_type, 1);
}

TEST(DNSParserTest, RejectsTooShort) {
    uint8_t data[] = {0x00, 0x01, 0x01};
    DNSHeader header;
    ASSERT_FALSE(parse_dns(data, sizeof(data), header));
}
