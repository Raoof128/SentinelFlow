#include "sentinelflow/parser/dns_parser.hpp"

#include <arpa/inet.h>

#include "sentinelflow/utils/byte_order.hpp"

namespace sf {

namespace {

constexpr uint32_t kDnsHeaderLength = 12;
constexpr uint16_t kDnsFlagResponse = 0x8000;  // QR bit
constexpr uint8_t kLabelTypeMask = 0xC0;       // top two bits of a label length byte
constexpr uint8_t kLabelTypePointer = 0xC0;    // 11: compression pointer
constexpr uint8_t kMaxLabelLength = 63;
constexpr uint32_t kMaxNameWireLength = 255;  // RFC 1035: length bytes, labels and the root

}  // namespace

bool parse_dns(const uint8_t* data, uint32_t length, DNSHeader& header) {
    if (length < kDnsHeaderLength)
        return false;
    header.transaction_id = read_be16(data);
    header.flags = read_be16(data + 2);
    header.is_response = (header.flags & kDnsFlagResponse) != 0;
    header.questions = read_be16(data + 4);
    header.answers = read_be16(data + 6);
    header.authority = read_be16(data + 8);
    header.additional = read_be16(data + 10);
    header.query_name.clear();
    header.query_type = 0;

    // Without a question there is no name: whatever follows the header is another section.
    if (header.questions == 0)
        return true;

    // Parse the first question's name (a sequence of length-prefixed labels).
    std::string name;
    uint32_t offset = kDnsHeaderLength;
    uint32_t wire_length = 1;  // the terminating root label
    bool terminated = false;
    while (offset < length) {
        const uint8_t label_len = data[offset];
        if (label_len == 0) {
            ++offset;
            terminated = true;
            break;
        }
        if ((label_len & kLabelTypeMask) == kLabelTypePointer) {
            // A compression pointer is two bytes and ends the name. The name in the first
            // question can only point back into the header, so there is nothing sensible to
            // follow; stop here instead of chasing offsets an attacker controls.
            if (offset + 2 > length)
                return false;
            offset += 2;
            terminated = true;
            break;
        }
        // Length bytes 0x40..0xBF use the reserved label types, not a length.
        if (label_len > kMaxLabelLength)
            return false;
        if (offset + 1 + label_len > length)
            return false;
        wire_length += 1u + label_len;
        if (wire_length > kMaxNameWireLength)
            return false;
        if (!name.empty())
            name += ".";
        name.append(reinterpret_cast<const char*>(data + offset + 1), label_len);
        offset += 1u + label_len;
    }
    if (!terminated)
        return false;
    header.query_name = std::move(name);

    // Query type
    if (offset + 2 <= length)
        header.query_type = read_be16(data + offset);

    return true;
}

}  // namespace sf
