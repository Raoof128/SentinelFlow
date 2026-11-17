#include "sentinelflow/pipeline/pipeline.hpp"

#include <algorithm>
#include <iostream>

#include "sentinelflow/parser/arp_parser.hpp"
#include "sentinelflow/parser/dns_parser.hpp"
#include "sentinelflow/parser/ethernet_parser.hpp"
#include "sentinelflow/parser/icmp_parser.hpp"
#include "sentinelflow/parser/ip_parser.hpp"
#include "sentinelflow/parser/tcp_parser.hpp"
#include "sentinelflow/parser/udp_parser.hpp"
#include "sentinelflow/utils/types.hpp"

namespace sf {

namespace {

constexpr uint32_t kEthernetHeaderLength = 14;
constexpr uint16_t kEtherTypeIPv4 = 0x0800;
constexpr uint16_t kEtherTypeARP = 0x0806;
constexpr uint8_t kIpProtocolICMP = 1;
constexpr uint8_t kIpProtocolTCP = 6;
constexpr uint8_t kIpProtocolUDP = 17;
constexpr uint16_t kIpFragmentOffsetMask = 0x1FFF;
constexpr uint16_t kDnsPort = 53;
constexpr uint32_t kUdpHeaderLength = 8;

void parse_tcp_segment(const uint8_t* segment, uint32_t length, ParsedPacket& pkt) {
    TCPHeader tcp;
    if (!parse_tcp(segment, length, tcp))
        return;
    pkt.tcp = tcp;
    // parse_tcp guarantees the header fits in `length`.
    const uint32_t header_length = tcp.data_offset * 4u;
    if (header_length < length) {
        pkt.payload = segment + header_length;
        pkt.payload_length = length - header_length;
    }
}

void parse_udp_datagram(const uint8_t* datagram, uint32_t length, ParsedPacket& pkt) {
    UDPHeader udp;
    if (!parse_udp(datagram, length, udp) || udp.length < kUdpHeaderLength)
        return;
    pkt.udp = udp;
    // The UDP length field says where the datagram ends; anything after it is padding. A first
    // fragment can carry less than the field claims, so never go past what was captured.
    const uint32_t datagram_length = std::min<uint32_t>(udp.length, length);
    if (datagram_length > kUdpHeaderLength) {
        pkt.payload = datagram + kUdpHeaderLength;
        pkt.payload_length = datagram_length - kUdpHeaderLength;
        if (udp.src_port == kDnsPort || udp.dst_port == kDnsPort) {
            DNSHeader dns;
            if (parse_dns(pkt.payload, pkt.payload_length, dns))
                pkt.dns = dns;
        }
    }
}

void parse_ipv4_packet(const uint8_t* data, uint32_t available, ParsedPacket& pkt) {
    IPv4Header ip;
    if (!parse_ipv4(data, available, ip))
        return;
    const uint32_t header_length = ip.ihl * 4u;

    // How many of the captured bytes belong to this IP packet.
    uint32_t ip_length = available;
    if (ip.total_length != 0) {
        if (ip.total_length < header_length)
            return;
        ip_length = std::min<uint32_t>(ip.total_length, available);
    }
    pkt.ipv4 = ip;

    // Only the first fragment carries the transport header.
    if ((ip.flags_fragment & kIpFragmentOffsetMask) != 0)
        return;

    const uint8_t* payload = data + header_length;
    const uint32_t payload_length = ip_length - header_length;
    switch (ip.protocol) {
        case kIpProtocolTCP:
            parse_tcp_segment(payload, payload_length, pkt);
            break;
        case kIpProtocolUDP:
            parse_udp_datagram(payload, payload_length, pkt);
            break;
        case kIpProtocolICMP: {
            ICMPHeader icmp;
            if (parse_icmp(payload, payload_length, icmp))
                pkt.icmp = icmp;
            break;
        }
        default:
            break;
    }
}

void print_packet(const ParsedPacket& pkt, uint32_t length) {
    if (pkt.ipv4) {
        std::cout << ip_to_string(pkt.ipv4->src_ip);
        if (pkt.tcp)
            std::cout << ":" << pkt.tcp->src_port;
        else if (pkt.udp)
            std::cout << ":" << pkt.udp->src_port;
        std::cout << " -> " << ip_to_string(pkt.ipv4->dst_ip);
        if (pkt.tcp)
            std::cout << ":" << pkt.tcp->dst_port;
        else if (pkt.udp)
            std::cout << ":" << pkt.udp->dst_port;

        if (pkt.tcp) {
            std::cout << " [TCP";
            if (pkt.tcp->flags & TCP_SYN)
                std::cout << " SYN";
            if (pkt.tcp->flags & TCP_ACK)
                std::cout << " ACK";
            if (pkt.tcp->flags & TCP_FIN)
                std::cout << " FIN";
            if (pkt.tcp->flags & TCP_RST)
                std::cout << " RST";
            if (pkt.tcp->flags & TCP_PSH)
                std::cout << " PSH";
            std::cout << "]";
        } else if (pkt.udp) {
            std::cout << " [UDP]";
            if (pkt.dns)
                std::cout << (pkt.dns->is_response ? " DNS-RESPONSE:" : " DNS:")
                          << pkt.dns->query_name;
        } else if (pkt.icmp) {
            std::cout << " [ICMP type=" << (int)pkt.icmp->type << "]";
        }
        std::cout << " len=" << length << std::endl;
    } else if (pkt.arp) {
        std::cout << ip_to_string(pkt.arp->sender_ip) << " -> " << ip_to_string(pkt.arp->target_ip)
                  << " [ARP opcode=" << pkt.arp->opcode << "]" << std::endl;
    }
}

}  // namespace

std::optional<ParsedPacket> parse_packet(const uint8_t* data, uint32_t length,
                                         std::chrono::system_clock::time_point ts) {
    ParsedPacket pkt;
    pkt.timestamp = ts;
    pkt.raw_data = data;
    pkt.raw_length = length;
    pkt.length = length;

    // Layer 2: Ethernet
    if (!parse_ethernet(data, length, pkt.ethernet))
        return std::nullopt;

    const uint8_t* l3 = data + kEthernetHeaderLength;
    const uint32_t l3_length = length - kEthernetHeaderLength;

    if (pkt.ethernet.ether_type == kEtherTypeARP) {
        ARPHeader arp;
        if (parse_arp(l3, l3_length, arp))
            pkt.arp = arp;
    } else if (pkt.ethernet.ether_type == kEtherTypeIPv4) {
        parse_ipv4_packet(l3, l3_length, pkt);
    }
    return pkt;
}

void process_packet(const uint8_t* data, uint32_t length, std::chrono::system_clock::time_point ts,
                    DetectionEngine& engine, AlertManager& alerts, TrafficStats& stats,
                    bool verbose) {
    auto parsed = parse_packet(data, length, ts);
    if (!parsed)
        return;
    const ParsedPacket& pkt = *parsed;

    stats.record(pkt);

    if (verbose)
        print_packet(pkt, length);

    // Run detection
    auto detected = engine.analyze(pkt);
    if (!detected.empty())
        alerts.process(detected);
}

}  // namespace sf
