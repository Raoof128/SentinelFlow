// End-to-end benchmark: a synthetic mix of Ethernet frames goes through the library pipeline
// (framing, parsing, stats, signature rules, stateful detectors, alert dispatch) on one thread.
//
// What the figure is: packets per second through process_packet() with the default rules, on
// synthetic traffic, in this process, on this machine. It is not a capture rate: no libpcap, no
// NIC, no disk, and console/CSV alert output is replaced by a counter. Real traffic differs from
// the mix below, so treat the figure as a regression yardstick rather than a capacity claim.
//
// Usage: benchmark_pipeline [rules-file] [packet-count]
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "sentinelflow/alert/alert_manager.hpp"
#include "sentinelflow/detection/detection_engine.hpp"
#include "sentinelflow/pipeline/pipeline.hpp"
#include "sentinelflow/stats/traffic_stats.hpp"

#ifndef SF_DEFAULT_RULES_PATH
    #define SF_DEFAULT_RULES_PATH "rules/default.rules"
#endif

using namespace sf;

namespace {

constexpr size_t kCorpusSize = 65536;  // distinct frames, replayed in a loop
constexpr uint64_t kDefaultPackets = 10'000'000;
constexpr uint64_t kWarmupPackets = 200'000;
constexpr auto kPacketSpacing = std::chrono::microseconds(20);  // simulated 50k packets/s

// Small deterministic PRNG so every run builds the same corpus.
class Rng {
public:
    uint32_t next() {
        state_ ^= state_ << 13;
        state_ ^= state_ >> 7;
        state_ ^= state_ << 17;
        return static_cast<uint32_t>(state_ >> 16);
    }
    uint32_t below(uint32_t n) { return next() % n; }

private:
    uint64_t state_ = 0x9E3779B97F4A7C15ull;
};

void put16(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v >> 8));
    out.push_back(static_cast<uint8_t>(v & 0xFF));
}

void put32(std::vector<uint8_t>& out, uint32_t v) {
    put16(out, static_cast<uint16_t>(v >> 16));
    put16(out, static_cast<uint16_t>(v & 0xFFFF));
}

std::vector<uint8_t> ipv4_frame(uint8_t proto, uint32_t src, uint32_t dst,
                                const std::vector<uint8_t>& l4, uint16_t frag = 0) {
    std::vector<uint8_t> f(12, 0xAA);
    put16(f, 0x0800);
    f.push_back(0x45);
    f.push_back(0);
    put16(f, static_cast<uint16_t>(20 + l4.size()));
    put16(f, 1);
    put16(f, frag);
    f.push_back(64);
    f.push_back(proto);
    put16(f, 0);
    put32(f, src);
    put32(f, dst);
    f.insert(f.end(), l4.begin(), l4.end());
    if (f.size() < 60)
        f.resize(60, 0);  // Ethernet minimum frame size
    return f;
}

std::vector<uint8_t> tcp_frame(uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport,
                               uint8_t flags, size_t payload_len, Rng& rng) {
    std::vector<uint8_t> seg;
    put16(seg, sport);
    put16(seg, dport);
    put32(seg, 1);
    put32(seg, 1);
    seg.push_back(0x50);
    seg.push_back(flags);
    put16(seg, 8192);
    put16(seg, 0);
    put16(seg, 0);
    for (size_t i = 0; i < payload_len; ++i)
        seg.push_back(static_cast<uint8_t>('a' + rng.below(26)));
    return ipv4_frame(6, src, dst, seg);
}

std::vector<uint8_t> dns_frame(uint32_t src, uint32_t dst, size_t name_len, bool response,
                               Rng& rng) {
    std::vector<uint8_t> msg;
    put16(msg, static_cast<uint16_t>(rng.next()));
    put16(msg, response ? 0x8180 : 0x0100);
    put16(msg, 1);
    put16(msg, response ? 1 : 0);
    put16(msg, 0);
    put16(msg, 0);
    // Labels of up to 20 characters, then a ".com" tail, adding up to about name_len.
    size_t remaining = name_len;
    while (remaining > 0) {
        const size_t label = std::min<size_t>(remaining, 20);
        msg.push_back(static_cast<uint8_t>(label));
        for (size_t i = 0; i < label; ++i)
            msg.push_back(static_cast<uint8_t>('a' + rng.below(26)));
        remaining -= label;
    }
    msg.push_back(3);
    msg.insert(msg.end(), {'c', 'o', 'm'});
    msg.push_back(0);
    put16(msg, 1);
    put16(msg, 1);

    std::vector<uint8_t> dgram;
    put16(dgram, response ? 53 : 40000);
    put16(dgram, response ? 40000 : 53);
    put16(dgram, static_cast<uint16_t>(8 + msg.size()));
    put16(dgram, 0);
    dgram.insert(dgram.end(), msg.begin(), msg.end());
    return ipv4_frame(17, src, dst, dgram);
}

std::vector<uint8_t> icmp_frame(uint32_t src, uint32_t dst) {
    std::vector<uint8_t> icmp = {8, 0, 0, 0, 0, 1, 0, 1};
    return ipv4_frame(1, src, dst, icmp);
}

std::vector<uint8_t> udp_frame(uint32_t src, uint32_t dst, Rng& rng) {
    std::vector<uint8_t> dgram;
    put16(dgram, static_cast<uint16_t>(1024 + rng.below(60000)));
    put16(dgram, static_cast<uint16_t>(1024 + rng.below(60000)));
    const size_t payload = 20 + rng.below(200);
    put16(dgram, static_cast<uint16_t>(8 + payload));
    put16(dgram, 0);
    dgram.insert(dgram.end(), payload, 0x5A);
    return ipv4_frame(17, src, dst, dgram);
}

std::vector<uint8_t> arp_frame(uint32_t src, uint32_t dst) {
    std::vector<uint8_t> f(12, 0xBB);
    put16(f, 0x0806);
    put16(f, 1);
    put16(f, 0x0800);
    f.push_back(6);
    f.push_back(4);
    put16(f, 1);
    f.insert(f.end(), 6, 0xAA);
    put32(f, src);
    f.insert(f.end(), 6, 0);
    put32(f, dst);
    return f;
}

// Roughly the shape of mixed traffic seen by an edge sensor, plus the traffic the detectors
// react to: SYNs from a large pool of sources, DNS queries long and short.
std::vector<std::vector<uint8_t>> build_corpus() {
    Rng rng;
    std::vector<std::vector<uint8_t>> corpus;
    corpus.reserve(kCorpusSize);
    constexpr uint32_t kClients = 0x0A000000;  // 10.0.0.0/8
    constexpr uint32_t kServers = 0xC0A80100;  // 192.168.1.0/24
    for (size_t i = 0; i < kCorpusSize; ++i) {
        const uint32_t client = kClients + rng.below(1u << 20);
        const uint32_t server = kServers + rng.below(250);
        const uint32_t pick = rng.below(100);
        if (pick < 45) {  // established TCP data
            // One random draw per statement: the order in which a call's arguments are evaluated
            // is up to the compiler, and the corpus must not depend on it.
            const uint16_t port = rng.below(2) ? 80 : 443;
            const auto src_port = static_cast<uint16_t>(30000 + rng.below(30000));
            const size_t payload = 20 + rng.below(400);
            corpus.push_back(tcp_frame(client, server, src_port, port, 0x18, payload, rng));
        } else if (pick < 60) {  // bare ACKs
            corpus.push_back(tcp_frame(server, client, 443,
                                       static_cast<uint16_t>(30000 + rng.below(30000)), 0x10, 0,
                                       rng));
        } else if (pick < 75) {  // SYNs to assorted ports from many sources
            static const uint16_t ports[] = {22, 23, 80, 443, 445, 3306, 3389, 5432, 8080};
            const uint16_t port =
                rng.below(4) ? ports[rng.below(9)] : static_cast<uint16_t>(1 + rng.below(65535));
            corpus.push_back(tcp_frame(client, server,
                                       static_cast<uint16_t>(30000 + rng.below(30000)), port, 0x02,
                                       0, rng));
        } else if (pick < 85) {  // DNS, mostly short names, a few long, some responses
            const bool response = rng.below(3) == 0;
            const size_t name_len = rng.below(10) == 0 ? 60 + rng.below(60) : 8 + rng.below(20);
            corpus.push_back(dns_frame(response ? 0x08080808 : client,
                                       response ? client : 0x08080808, name_len, response, rng));
        } else if (pick < 91) {
            corpus.push_back(icmp_frame(client, server));
        } else if (pick < 97) {
            corpus.push_back(udp_frame(client, server, rng));
        } else if (pick < 99) {
            corpus.push_back(arp_frame(client, server));
        } else {  // a non-first IP fragment
            std::vector<uint8_t> filler(64, 0x41);
            corpus.push_back(ipv4_frame(6, client, server, filler, 100));
        }
    }
    return corpus;
}

class CountingOutput : public AlertOutput {
public:
    explicit CountingOutput(uint64_t* counter) : counter_(counter) {}
    void emit(const Alert&) override { ++*counter_; }

private:
    uint64_t* counter_;
};

struct RunResult {
    uint64_t packets = 0;
    uint64_t bytes = 0;
    uint64_t alerts = 0;
    double seconds = 0;
    uint64_t tcp = 0, dns = 0, udp = 0, icmp = 0, arp = 0;  // what the parsers recognised
};

RunResult run(const std::vector<std::vector<uint8_t>>& corpus, const std::string& rules,
              uint64_t packets) {
    DetectionEngine engine;
    engine.load_rules(rules);
    AlertManager alert_manager;
    uint64_t alert_count = 0;
    alert_manager.add_output(std::make_unique<CountingOutput>(&alert_count));
    TrafficStats stats;

    auto ts = std::chrono::system_clock::from_time_t(1'800'000'000);
    uint64_t bytes = 0;
    const auto start = std::chrono::steady_clock::now();
    for (uint64_t i = 0; i < packets; ++i) {
        const auto& frame = corpus[i % corpus.size()];
        process_packet(frame.data(), static_cast<uint32_t>(frame.size()), ts, engine, alert_manager,
                       stats);
        bytes += frame.size();
        ts += kPacketSpacing;
    }
    const auto end = std::chrono::steady_clock::now();

    RunResult result;
    result.packets = packets;
    result.bytes = bytes;
    result.alerts = alert_count;
    result.tcp = stats.tcp_count();
    result.dns = stats.dns_count();
    result.udp = stats.udp_count();
    result.icmp = stats.icmp_count();
    result.arp = stats.arp_count();
    result.seconds = std::chrono::duration<double>(end - start).count();
    return result;
}

}  // namespace

int main(int argc, char* argv[]) {
    const std::string rules = argc > 1 ? argv[1] : SF_DEFAULT_RULES_PATH;
    const uint64_t packets = argc > 2 ? std::strtoull(argv[2], nullptr, 10) : kDefaultPackets;

    const auto corpus = build_corpus();
    run(corpus, rules, kWarmupPackets);  // warm caches and the allocator; not reported
    const RunResult r = run(corpus, rules, packets);

    std::cout << "=== SentinelFlow Pipeline Benchmark ===" << std::endl;
    std::cout << "Traffic:            synthetic mix, " << corpus.size()
              << " distinct frames replayed" << std::endl;
    std::cout << "Rules:              " << rules << std::endl;
    std::cout << "Threads:            1" << std::endl;
    std::cout << "Packets processed:  " << r.packets << std::endl;
    std::cout << "Bytes processed:    " << r.bytes << std::endl;
    std::cout << "Parsed as:          tcp=" << r.tcp << " dns=" << r.dns << " udp=" << r.udp
              << " icmp=" << r.icmp << " arp=" << r.arp << std::endl;
    std::cout << "Alerts raised:      " << r.alerts << std::endl;
    std::cout << "Elapsed time:       " << std::fixed << std::setprecision(0) << r.seconds * 1000
              << " ms" << std::endl;
    std::cout << "Throughput:         " << static_cast<uint64_t>(r.packets / r.seconds)
              << " packets/sec" << std::endl;
    std::cout << "Avg latency:        " << std::setprecision(3) << r.seconds * 1e6 / r.packets
              << " us/packet" << std::endl;
    return 0;
}
