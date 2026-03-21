#include "sentinelflow/capture/live_capture.hpp"
#include "sentinelflow/capture/pcap_file_reader.hpp"
#include "sentinelflow/parser/ethernet_parser.hpp"
#include "sentinelflow/parser/ip_parser.hpp"
#include "sentinelflow/parser/tcp_parser.hpp"
#include "sentinelflow/parser/udp_parser.hpp"
#include "sentinelflow/parser/icmp_parser.hpp"
#include "sentinelflow/parser/dns_parser.hpp"
#include "sentinelflow/parser/arp_parser.hpp"
#include "sentinelflow/detection/detection_engine.hpp"
#include "sentinelflow/alert/alert_manager.hpp"
#include "sentinelflow/alert/console_logger.hpp"
#include "sentinelflow/alert/csv_logger.hpp"
#include "sentinelflow/stats/traffic_stats.hpp"
#include "sentinelflow/utils/timestamp.hpp"
#include <iostream>
#include <iomanip>
#include <csignal>
#include <memory>

using namespace sf;

static bool running = true;
static bool verbose = false;
static TrafficStats* g_stats = nullptr;
static PacketCapture* g_capture = nullptr;

void signal_handler(int) {
    running = false;
    if (g_capture) g_capture->stop();
}

void process_packet(const uint8_t* data, uint32_t length,
                    std::chrono::system_clock::time_point ts,
                    DetectionEngine& engine, AlertManager& alerts,
                    TrafficStats& stats) {
    ParsedPacket pkt;
    pkt.timestamp  = ts;
    pkt.raw_data   = data;
    pkt.raw_length = length;
    pkt.length     = length;

    // Layer 2: Ethernet
    if (!parse_ethernet(data, length, pkt.ethernet)) return;

    uint32_t offset = 14;

    if (pkt.ethernet.ether_type == 0x0806 && length > offset) {
        // ARP
        ARPHeader arp;
        if (parse_arp(data + offset, length - offset, arp)) {
            pkt.arp = arp;
        }
    } else if (pkt.ethernet.ether_type == 0x0800 && length > offset) {
        // IPv4
        IPv4Header ip;
        if (parse_ipv4(data + offset, length - offset, ip)) {
            pkt.ipv4 = ip;
            uint32_t ip_header_len = ip.ihl * 4;
            offset += ip_header_len;

            if (ip.protocol == 6 && length > offset) {
                TCPHeader tcp;
                if (parse_tcp(data + offset, length - offset, tcp)) {
                    pkt.tcp = tcp;
                    uint32_t tcp_header_len = tcp.data_offset * 4;
                    if (offset + tcp_header_len < length) {
                        pkt.payload = data + offset + tcp_header_len;
                        pkt.payload_length = length - offset - tcp_header_len;
                    }
                }
            } else if (ip.protocol == 17 && length > offset) {
                UDPHeader udp;
                if (parse_udp(data + offset, length - offset, udp)) {
                    pkt.udp = udp;
                    if (udp.src_port == 53 || udp.dst_port == 53) {
                        uint32_t dns_offset = offset + 8;
                        if (dns_offset < length) {
                            DNSHeader dns;
                            if (parse_dns(data + dns_offset, length - dns_offset, dns)) {
                                pkt.dns = dns;
                            }
                        }
                    }
                    pkt.payload = data + offset + 8;
                    pkt.payload_length = length - offset - 8;
                }
            } else if (ip.protocol == 1 && length > offset) {
                ICMPHeader icmp;
                if (parse_icmp(data + offset, length - offset, icmp)) {
                    pkt.icmp = icmp;
                }
            }
        }
    }

    stats.record(pkt);

    // Verbose: print every packet
    if (verbose && pkt.ipv4) {
        std::cout << ip_to_string(pkt.ipv4->src_ip);
        if (pkt.tcp)       std::cout << ":" << pkt.tcp->src_port;
        else if (pkt.udp)  std::cout << ":" << pkt.udp->src_port;
        std::cout << " -> " << ip_to_string(pkt.ipv4->dst_ip);
        if (pkt.tcp)       std::cout << ":" << pkt.tcp->dst_port;
        else if (pkt.udp)  std::cout << ":" << pkt.udp->dst_port;

        if (pkt.tcp) {
            std::cout << " [TCP";
            if (pkt.tcp->flags & TCP_SYN) std::cout << " SYN";
            if (pkt.tcp->flags & TCP_ACK) std::cout << " ACK";
            if (pkt.tcp->flags & TCP_FIN) std::cout << " FIN";
            if (pkt.tcp->flags & TCP_RST) std::cout << " RST";
            if (pkt.tcp->flags & TCP_PSH) std::cout << " PSH";
            std::cout << "]";
        } else if (pkt.udp) {
            std::cout << " [UDP]";
            if (pkt.dns) std::cout << " DNS:" << pkt.dns->query_name;
        } else if (pkt.icmp) {
            std::cout << " [ICMP type=" << (int)pkt.icmp->type << "]";
        }
        std::cout << " len=" << length << std::endl;
    } else if (verbose && pkt.arp) {
        std::cout << ip_to_string(pkt.arp->sender_ip) << " -> "
                  << ip_to_string(pkt.arp->target_ip)
                  << " [ARP opcode=" << pkt.arp->opcode << "]"
                  << std::endl;
    }

    // Run detection
    auto detected = engine.analyze(pkt);
    if (!detected.empty()) {
        alerts.process(detected);
    }
}

void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " [OPTIONS] [INTERFACE]\n"
              << "\nOptions:\n"
              << "  --pcap FILE       Read packets from .pcap file\n"
              << "  --rules FILE      Load detection rules (default: rules/default.rules)\n"
              << "  --log FILE        Write alerts to CSV log file\n"
              << "  --filter EXPR     Set BPF filter (e.g., 'tcp port 80')\n"
              << "  -v, --verbose     Print every packet (like Wireshark)\n"
              << "  -h, --help        Show this help\n"
              << "\nExamples:\n"
              << "  sudo " << prog << " en0\n"
              << "  " << prog << " --pcap capture.pcap\n"
              << "  sudo " << prog << " --rules rules/default.rules --log alerts.csv en0\n";
}

int main(int argc, char* argv[]) {
    std::string iface = "en0";
    std::string pcap_file;
    std::string rules_file = "rules/default.rules";
    std::string log_file;
    std::string bpf_filter;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--pcap" && i + 1 < argc) {
            pcap_file = argv[++i];
        } else if (arg == "--rules" && i + 1 < argc) {
            rules_file = argv[++i];
        } else if (arg == "--log" && i + 1 < argc) {
            log_file = argv[++i];
        } else if (arg == "--filter" && i + 1 < argc) {
            bpf_filter = argv[++i];
        } else if (arg == "-v" || arg == "--verbose") {
            verbose = true;
        } else if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else {
            iface = arg;
        }
    }

    std::cout << "=== SentinelFlow v1.0 ===" << std::endl;

    // Set up detection
    DetectionEngine engine;
    engine.load_rules(rules_file);

    // Set up alerting
    AlertManager alert_manager;
    alert_manager.add_output(std::make_unique<ConsoleLogger>());
    if (!log_file.empty()) {
        alert_manager.add_output(std::make_unique<CsvLogger>(log_file));
        std::cout << "Logging alerts to: " << log_file << std::endl;
    }

    // Set up stats
    TrafficStats stats;
    g_stats = &stats;

    // Create capture source
    std::unique_ptr<PacketCapture> capture;
    if (!pcap_file.empty()) {
        std::cout << "Reading from file: " << pcap_file << std::endl;
        capture = std::make_unique<PcapFileReader>(pcap_file);
    } else {
        std::cout << "Capturing on interface: " << iface << std::endl;
        capture = std::make_unique<LiveCapture>(iface);
    }

    g_capture = capture.get();
    std::signal(SIGINT, signal_handler);

    if (!capture->open()) {
        std::cerr << "Failed to open capture source. ";
        if (pcap_file.empty()) std::cerr << "Try running with sudo.";
        std::cerr << std::endl;
        return 1;
    }

    if (!bpf_filter.empty()) {
        if (!capture->set_filter(bpf_filter)) {
            std::cerr << "Failed to set BPF filter: " << bpf_filter << std::endl;
            return 1;
        }
        std::cout << "Filter: " << bpf_filter << std::endl;
    }

    std::cout << "Press Ctrl+C to stop" << std::endl;
    std::cout << std::string(50, '-') << std::endl;

    capture->start([&](const uint8_t* data, uint32_t length,
                       std::chrono::system_clock::time_point ts) {
        if (running) {
            process_packet(data, length, ts, engine, alert_manager, stats);
        }
    });

    stats.print_summary();
    std::cout << "Total alerts: " << alert_manager.total_alerts() << std::endl;

    return 0;
}
