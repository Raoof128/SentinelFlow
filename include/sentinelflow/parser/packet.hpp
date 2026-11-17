#pragma once
#include <optional>
#include <vector>

#include "sentinelflow/utils/types.hpp"

namespace sf {

enum class Protocol : uint8_t { UNKNOWN = 0, ETHERNET, ARP, IPv4, TCP, UDP, ICMP, DNS };

struct EthernetHeader {
    MacAddress src_mac;
    MacAddress dst_mac;
    uint16_t ether_type;
};

struct IPv4Header {
    uint8_t version;
    uint8_t ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    IPv4Address src_ip;
    IPv4Address dst_ip;
};

struct TCPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_number;
    uint32_t ack_number;
    uint8_t data_offset;
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_ptr;
};

constexpr uint8_t TCP_FIN = 0x01;
constexpr uint8_t TCP_SYN = 0x02;
constexpr uint8_t TCP_RST = 0x04;
constexpr uint8_t TCP_PSH = 0x08;
constexpr uint8_t TCP_ACK = 0x10;
constexpr uint8_t TCP_URG = 0x20;

struct UDPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};

struct ICMPHeader {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequence;
};

struct DNSHeader {
    uint16_t transaction_id;
    uint16_t flags;
    uint16_t questions;
    uint16_t answers;
    uint16_t authority;
    uint16_t additional;
    std::string query_name;
    uint16_t query_type;
};

struct ARPHeader {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t hw_size;
    uint8_t proto_size;
    uint16_t opcode;
    MacAddress sender_mac;
    IPv4Address sender_ip;
    MacAddress target_mac;
    IPv4Address target_ip;
};

struct ParsedPacket {
    std::chrono::system_clock::time_point timestamp;
    uint32_t length = 0;
    const uint8_t* raw_data = nullptr;
    uint32_t raw_length = 0;

    EthernetHeader ethernet{};
    std::optional<IPv4Header> ipv4;
    std::optional<TCPHeader> tcp;
    std::optional<UDPHeader> udp;
    std::optional<ICMPHeader> icmp;
    std::optional<DNSHeader> dns;
    std::optional<ARPHeader> arp;

    const uint8_t* payload = nullptr;
    uint32_t payload_length = 0;

    Protocol highest_protocol() const {
        if (dns)
            return Protocol::DNS;
        if (tcp)
            return Protocol::TCP;
        if (udp)
            return Protocol::UDP;
        if (icmp)
            return Protocol::ICMP;
        if (arp)
            return Protocol::ARP;
        if (ipv4)
            return Protocol::IPv4;
        return Protocol::ETHERNET;
    }
};

}  // namespace sf
