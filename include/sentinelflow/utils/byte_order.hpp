#pragma once

#include <cstdint>
#include <cstring>

#include <arpa/inet.h>

namespace sf {

/// Read a big-endian 16-bit field from a packet buffer.
///
/// Packet fields sit at arbitrary offsets, so they are not guaranteed to be
/// aligned for `uint16_t`. Copying the bytes out avoids the unaligned load and
/// the strict-aliasing violation that casting the pointer would cause.
inline uint16_t read_be16(const uint8_t* data) {
    uint16_t value;
    std::memcpy(&value, data, sizeof(value));
    return ntohs(value);
}

/// Read a big-endian 32-bit field from a packet buffer. See read_be16.
inline uint32_t read_be32(const uint8_t* data) {
    uint32_t value;
    std::memcpy(&value, data, sizeof(value));
    return ntohl(value);
}

}  // namespace sf
