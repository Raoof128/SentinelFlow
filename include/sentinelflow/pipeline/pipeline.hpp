#pragma once
#include <chrono>
#include <cstdint>
#include <optional>

#include "sentinelflow/alert/alert_manager.hpp"
#include "sentinelflow/detection/detection_engine.hpp"
#include "sentinelflow/parser/packet.hpp"
#include "sentinelflow/stats/traffic_stats.hpp"

namespace sf {

/// Frame and parse one captured Ethernet frame.
///
/// Framing rules:
///  - IPv4 data is trimmed to the header's total length, so Ethernet padding is never read as
///    payload. A total length of 0 (a placeholder some capture offloads leave in outgoing
///    frames) means "use everything that was captured". A total length shorter than the IP
///    header makes the IPv4 layer invalid. A total length beyond the captured bytes (a snap-
///    length-truncated frame) is clamped to what is there.
///  - A non-first fragment (non-zero fragment offset) has no transport header: the IPv4 layer is
///    parsed and nothing above it.
///  - TCP is rejected if its data offset is below 5 words or beyond the segment; UDP if its
///    length field is below 8. UDP payload is trimmed to the UDP length.
///  - DNS is parsed from the UDP payload when either port is 53.
///
/// Returns nullopt only when the frame is too short to hold an Ethernet header. The packet's
/// `raw_data` and `payload` pointers refer into `data`, which must outlive the result.
std::optional<ParsedPacket> parse_packet(const uint8_t* data, uint32_t length,
                                         std::chrono::system_clock::time_point ts);

/// Parse one frame, record it in `stats`, run it through `engine` and hand any alerts to
/// `alerts`. With `verbose`, also print a one-line summary of the packet to stdout.
void process_packet(const uint8_t* data, uint32_t length, std::chrono::system_clock::time_point ts,
                    DetectionEngine& engine, AlertManager& alerts, TrafficStats& stats,
                    bool verbose = false);

}  // namespace sf
