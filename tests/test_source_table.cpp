#include <chrono>
#include <cstdint>

#include <gtest/gtest.h>

#include "sentinelflow/detection/source_table.hpp"

using namespace sf;

namespace {

struct Counter {
    std::size_t events = 0;
    std::size_t progress() const { return events; }
};

using Table = SourceTable<uint32_t, Counter>;
const auto kT0 = std::chrono::system_clock::now();

}  // namespace

TEST(SourceTableTest, ExpiredRecordsGoBeforeLiveOnes) {
    Table table(3);
    table.touch(1, kT0).events = 1;
    table.touch(2, kT0).events = 1;
    table.touch(3, kT0 + std::chrono::seconds(50)).events = 1;

    // Detectors evict idle records before touching: records 1 and 2 are expired, 3 is live.
    const auto now = kT0 + std::chrono::seconds(61);
    table.evict_idle(now - std::chrono::seconds(60));
    table.touch(4, now);

    EXPECT_EQ(table.size(), 2u);
    EXPECT_EQ(table.capacity_evictions(), 0u);  // nothing live was dropped
    EXPECT_EQ(table.touch(3, now).events, 1u);  // record 3 is still there with its state
}

TEST(SourceTableTest, RecordCloseToItsThresholdOutlivesAFloodOfNewOnes) {
    Table table(10);
    table.touch(1, kT0).events = 4;  // oldest, and the only one with any progress
    for (uint32_t key = 100; key < 1100; ++key)
        table.touch(key, kT0).events = 1;

    EXPECT_EQ(table.size(), 10u);
    EXPECT_EQ(table.capacity_evictions(), 991u);
    EXPECT_EQ(table.touch(1, kT0).events, 4u);
}

TEST(SourceTableTest, EqualProgressEvictsTheOldest) {
    Table table(3);
    table.touch(1, kT0).events = 1;
    table.touch(2, kT0).events = 1;
    table.touch(3, kT0).events = 1;
    table.touch(4, kT0).events = 1;  // full: 1 is the oldest of equals

    EXPECT_EQ(table.touch(2, kT0).events, 1u);
    EXPECT_EQ(table.touch(3, kT0).events, 1u);
    EXPECT_EQ(table.touch(1, kT0).events, 0u);  // 1 was evicted: a fresh record
}

TEST(SourceTableTest, OnlyTheOldestFewAreConsidered) {
    // Eviction looks at a fixed number of records at the cold end, so its cost is constant.
    // A record with little progress outside that group is not chosen over one inside it.
    Table table(kEvictionCandidates + 2);
    for (uint32_t key = 1; key <= kEvictionCandidates; ++key)
        table.touch(key, kT0).events = 5;  // the oldest group: all well advanced
    table.touch(100, kT0).events = 0;      // newer and with no progress
    table.touch(101, kT0).events = 0;
    table.touch(200, kT0);  // full: victim comes from keys 1..8

    EXPECT_EQ(table.capacity_evictions(), 1u);
    EXPECT_EQ(table.touch(100, kT0).events, 0u);  // untouched either way; check 1 is gone
    EXPECT_EQ(table.touch(1, kT0).events, 0u);    // key 1 (oldest of equals) was the victim
}

TEST(SourceTableTest, IdleEvictionIsNotCountedAsCapacityEviction) {
    Table table(100);
    for (uint32_t key = 0; key < 50; ++key)
        table.touch(key, kT0);
    table.evict_idle(kT0 + std::chrono::seconds(1));

    EXPECT_EQ(table.size(), 0u);
    EXPECT_EQ(table.capacity_evictions(), 0u);
}
