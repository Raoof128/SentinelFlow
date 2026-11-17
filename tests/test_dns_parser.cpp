#include <string>
#include <vector>

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
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm',
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

namespace {

// Header for a standard query with one question.
std::vector<uint8_t> dns_header(uint16_t flags = 0x0100, uint16_t questions = 1) {
    return {0x00,
            0x01,
            static_cast<uint8_t>(flags >> 8),
            static_cast<uint8_t>(flags & 0xFF),
            static_cast<uint8_t>(questions >> 8),
            static_cast<uint8_t>(questions & 0xFF),
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00};
}

void append_label(std::vector<uint8_t>& out, const std::string& label) {
    out.push_back(static_cast<uint8_t>(label.size()));
    out.insert(out.end(), label.begin(), label.end());
}

void append_question_tail(std::vector<uint8_t>& out) {
    out.insert(out.end(), {0x00, 0x00, 0x01, 0x00, 0x01});  // root, type A, class IN
}

}  // namespace

TEST(DNSParserTest, RejectsLabelLongerThan63) {
    // Length byte 0x80 is not a valid label length (the top two bits are reserved); the old
    // parser read it as a 128-byte label.
    auto data = dns_header();
    data.push_back(0x80);
    data.insert(data.end(), 128, 'a');
    append_question_tail(data);

    DNSHeader header;
    EXPECT_FALSE(parse_dns(data.data(), data.size(), header));
}

TEST(DNSParserTest, AcceptsLabelOfExactly63) {
    auto data = dns_header();
    append_label(data, std::string(63, 'a'));
    append_question_tail(data);

    DNSHeader header;
    ASSERT_TRUE(parse_dns(data.data(), data.size(), header));
    EXPECT_EQ(header.query_name, std::string(63, 'a'));
}

TEST(DNSParserTest, CompressionPointerEndsTheName) {
    // "www" followed by a pointer to offset 12. The pointer is two bytes and ends the name; the
    // old parser read 0xC0 as a 192-byte label and rejected or mangled the packet.
    auto data = dns_header();
    append_label(data, "www");
    data.insert(data.end(), {0xC0, 0x0C});
    data.insert(data.end(), {0x00, 0x1C, 0x00, 0x01});  // type AAAA, class IN

    DNSHeader header;
    ASSERT_TRUE(parse_dns(data.data(), data.size(), header));
    EXPECT_EQ(header.query_name, "www");
    EXPECT_EQ(header.query_type, 28);
}

TEST(DNSParserTest, RejectsTruncatedCompressionPointer) {
    auto data = dns_header();
    data.push_back(0xC0);  // pointer needs a second byte

    DNSHeader header;
    EXPECT_FALSE(parse_dns(data.data(), data.size(), header));
}

TEST(DNSParserTest, RejectsNameLongerThan255) {
    auto data = dns_header();
    for (int i = 0; i < 5; ++i)
        append_label(data, std::string(60, 'a'));  // 5 * 61 = 305 bytes on the wire
    append_question_tail(data);

    DNSHeader header;
    EXPECT_FALSE(parse_dns(data.data(), data.size(), header));
}

TEST(DNSParserTest, RejectsUnterminatedName) {
    auto data = dns_header();
    append_label(data, "example");  // no root label, no more bytes

    DNSHeader header;
    EXPECT_FALSE(parse_dns(data.data(), data.size(), header));
}

TEST(DNSParserTest, NoQuestionsMeansNoName) {
    // With QDCOUNT = 0 the bytes after the header are not a name.
    auto data = dns_header(0x8180, 0);
    data.insert(data.end(), {0x03, 'f', 'o', 'o', 0x00});

    DNSHeader header;
    ASSERT_TRUE(parse_dns(data.data(), data.size(), header));
    EXPECT_TRUE(header.query_name.empty());
}

TEST(DNSParserTest, ReportsQueryVersusResponse) {
    auto query = dns_header(0x0100);
    append_label(query, "example");
    append_label(query, "com");
    append_question_tail(query);
    DNSHeader header;
    ASSERT_TRUE(parse_dns(query.data(), query.size(), header));
    EXPECT_FALSE(header.is_response);

    auto response = dns_header(0x8180);
    append_label(response, "example");
    append_label(response, "com");
    append_question_tail(response);
    ASSERT_TRUE(parse_dns(response.data(), response.size(), header));
    EXPECT_TRUE(header.is_response);
    EXPECT_EQ(header.query_name, "example.com");
}
