#include <csignal>
#include <iomanip>
#include <iostream>
#include <memory>

#include "sentinelflow/alert/alert_manager.hpp"
#include "sentinelflow/alert/console_logger.hpp"
#include "sentinelflow/alert/csv_logger.hpp"
#include "sentinelflow/capture/live_capture.hpp"
#include "sentinelflow/capture/pcap_file_reader.hpp"
#include "sentinelflow/detection/detection_engine.hpp"
#include "sentinelflow/pipeline/pipeline.hpp"
#include "sentinelflow/stats/traffic_stats.hpp"
#include "sentinelflow/utils/timestamp.hpp"

using namespace sf;

static bool running = true;
static bool verbose = false;
static PacketCapture* g_capture = nullptr;

void signal_handler(int) {
    running = false;
    if (g_capture)
        g_capture->stop();
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

    std::cout << "=== SentinelFlow v" << SENTINELFLOW_VERSION << " ===" << std::endl;

    // Set up detection
    DetectionEngine engine;
    auto rule_stats = engine.load_rules(rules_file);
    std::cout << "Loaded " << rule_stats.loaded << " rules from " << rules_file;
    if (rule_stats.rejected > 0)
        std::cout << " (" << rule_stats.rejected << " rejected, see warnings above)";
    std::cout << std::endl;

    // Set up alerting
    AlertManager alert_manager;
    alert_manager.add_output(std::make_unique<ConsoleLogger>());
    if (!log_file.empty()) {
        alert_manager.add_output(std::make_unique<CsvLogger>(log_file));
        std::cout << "Logging alerts to: " << log_file << std::endl;
    }

    // Set up stats
    TrafficStats stats;

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
        if (pcap_file.empty())
            std::cerr << "Try running with sudo.";
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

    capture->start(
        [&](const uint8_t* data, uint32_t length, std::chrono::system_clock::time_point ts) {
            if (running) {
                process_packet(data, length, ts, engine, alert_manager, stats, verbose);
            }
        });

    stats.print_summary();
    const auto evictions = engine.state_evictions();
    if (evictions.total() > 0) {
        std::cout << "Warning: detector state tables were full and dropped " << evictions.total()
                  << " tracked records (port scan " << evictions.port_scan << ", SYN flood "
                  << evictions.syn_flood << ", DNS tunnel " << evictions.dns_tunnel
                  << "); detection of slow or distributed activity was degraded" << std::endl;
    }
    std::cout << "Total alerts: " << alert_manager.total_alerts() << std::endl;

    return 0;
}
