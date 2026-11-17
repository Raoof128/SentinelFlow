#include <cstdio>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <pcap.h>

#include "sentinelflow/capture/pcap_file_reader.hpp"

using namespace sf;

namespace {

// Write a pcap file with the given link type and `count` identical 60-byte packets.
std::string write_pcap(const std::string& name, int link_type, int count) {
    const std::string path = testing::TempDir() + name;
    pcap_t* dead = pcap_open_dead(link_type, 65535);
    pcap_dumper_t* dumper = pcap_dump_open(dead, path.c_str());
    EXPECT_NE(dumper, nullptr);
    std::vector<uint8_t> frame(60, 0);
    for (int i = 0; i < count; ++i) {
        pcap_pkthdr hdr{};
        hdr.ts.tv_sec = 1'800'000'000 + i;
        hdr.caplen = hdr.len = static_cast<bpf_u_int32>(frame.size());
        pcap_dump(reinterpret_cast<u_char*>(dumper), &hdr, frame.data());
    }
    pcap_dump_close(dumper);
    pcap_close(dead);
    return path;
}

}  // namespace

TEST(PcapFileReaderTest, OpensAndReplaysEthernetCapture) {
    const std::string path = write_pcap("sf_ethernet.pcap", DLT_EN10MB, 3);
    PcapFileReader reader(path);
    ASSERT_TRUE(reader.open());

    int packets = 0;
    reader.start([&](const uint8_t*, uint32_t length, std::chrono::system_clock::time_point) {
        EXPECT_EQ(length, 60u);
        ++packets;
    });
    EXPECT_EQ(packets, 3);
    std::remove(path.c_str());
}

TEST(PcapFileReaderTest, RefusesNonEthernetLinkType) {
    // DLT_NULL is the BSD loopback format (a 4-byte family header, no MAC addresses). Parsing it
    // as Ethernet would read garbage, so the reader must refuse it.
    const std::string path = write_pcap("sf_null.pcap", DLT_NULL, 1);
    PcapFileReader reader(path);

    testing::internal::CaptureStderr();
    const bool opened = reader.open();
    const std::string log = testing::internal::GetCapturedStderr();

    EXPECT_FALSE(opened);
    EXPECT_NE(log.find("link"), std::string::npos) << log;
    EXPECT_NE(log.find("Ethernet"), std::string::npos) << log;
    std::remove(path.c_str());
}

TEST(PcapFileReaderTest, RefusesRawIpLinkType) {
    const std::string path = write_pcap("sf_raw.pcap", DLT_RAW, 1);
    PcapFileReader reader(path);

    testing::internal::CaptureStderr();
    EXPECT_FALSE(reader.open());
    testing::internal::GetCapturedStderr();
    std::remove(path.c_str());
}

TEST(PcapFileReaderTest, ReportsMissingFile) {
    PcapFileReader reader(testing::TempDir() + "sf_does_not_exist.pcap");
    testing::internal::CaptureStderr();
    EXPECT_FALSE(reader.open());
    testing::internal::GetCapturedStderr();
}
