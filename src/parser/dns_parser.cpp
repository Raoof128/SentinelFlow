#include "sentinelflow/parser/dns_parser.hpp"

#include <arpa/inet.h>

#include "sentinelflow/utils/byte_order.hpp"

namespace sf {

bool parse_dns(const uint8_t* data, uint32_t length, DNSHeader& header) {
    if (length < 12)
        return false;
    header.transaction_id = read_be16(data);
    header.flags = read_be16(data + 2);
    header.questions = read_be16(data + 4);
    header.answers = read_be16(data + 6);
    header.authority = read_be16(data + 8);
    header.additional = read_be16(data + 10);

    // Parse query name (DNS label format)
    header.query_name.clear();
    uint32_t offset = 12;
    while (offset < length) {
        uint8_t label_len = data[offset];
        if (label_len == 0) {
            offset++;
            break;
        }
        if (offset + 1 + label_len > length)
            return false;
        if (!header.query_name.empty())
            header.query_name += ".";
        header.query_name.append(reinterpret_cast<const char*>(data + offset + 1), label_len);
        offset += 1 + label_len;
    }

    // Query type
    if (offset + 2 <= length) {
        header.query_type = read_be16(data + offset);
    } else {
        header.query_type = 0;
    }

    return true;
}

}  // namespace sf
