#pragma once
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <list>
#include <unordered_map>

namespace sf {

/// Default cap on the number of sources (or source/destination pairs) a stateful detector tracks
/// at once, so a stream of spoofed addresses cannot grow memory without bound.
///
/// Worst-case memory is this many entries times the per-entry state, which each detector keeps
/// to O(threshold). Every detector takes the cap as a constructor argument.
///
/// A bounded table can be attacked: an attacker who can spoof enough distinct sources can fill
/// it and push other sources' state out, which resets their counts. The table cannot prevent
/// that, only make it expensive and visible (see capacity_evictions() and the "state table
/// pressure" alert). What it does to make it harder is in the eviction policy below.
constexpr std::size_t kDefaultMaxTrackedSources = 65536;

/// When the table is full, the victim is chosen among this many of the least recently updated
/// records. A fixed number keeps the cost per packet constant.
constexpr std::size_t kEvictionCandidates = 8;

/// Per-key detector state with a bounded size.
///
/// Records are kept in the order they were last updated, most recent first. That order serves
/// three purposes:
///   - evict_idle() drops records not updated since a cutoff time by looking only at the cold
///     end of the list, so each record is examined once on its way out and the cost per packet is
///     amortised constant. Callers run it before touch(), so by the time the table is full
///     every expired record is already gone: expired records always go before live ones;
///   - touch() makes room, when the table is full, by dropping one of the kEvictionCandidates
///     least recently updated records: the one with the least progress towards its alert
///     threshold (Record::progress(), ties to the oldest). A record that is close to alerting
///     therefore outlives the single-packet records an attacker sprays to flush the table;
///   - both operations are O(1) (O(kEvictionCandidates) at worst).
///
/// Trade-offs. The choice is among the oldest few records, not all of them, so it is a heuristic
/// and not the exact "furthest from its threshold" record. An attacker who can make more than
/// kEvictionCandidates records each as close to the threshold as the victim can still evict it.
/// Every eviction at capacity is counted in capacity_evictions() so that the pressure is
/// visible.
///
/// Record must provide `std::size_t progress() const`: how far the record is towards raising its
/// alert (a count of the events it holds). All records in one table share a threshold, so the
/// raw counts compare directly.
///
/// Callers must pass non-decreasing times to touch() for evict_idle() to see every idle record;
/// the detectors keep a high-water mark of packet time and use that.
template <typename Key, typename Record> class SourceTable {
public:
    using TimePoint = std::chrono::system_clock::time_point;

    explicit SourceTable(std::size_t max_entries) : max_entries_(max_entries ? max_entries : 1) {}

    /// Find or create the record for `key` and mark it as updated at `now`.
    Record& touch(const Key& key, TimePoint now) {
        auto found = map_.find(key);
        if (found != map_.end()) {
            order_.splice(order_.begin(), order_, found->second.position);
            found->second.last_update = now;
            return found->second.record;
        }
        if (map_.size() >= max_entries_)
            evict_for_capacity();
        order_.push_front(key);
        auto inserted = map_.emplace(key, Slot{Record{}, now, order_.begin()});
        return inserted.first->second.record;
    }

    /// Drop every record whose last update is before `cutoff`.
    void evict_idle(TimePoint cutoff) {
        while (!order_.empty()) {
            auto found = map_.find(order_.back());
            if (found->second.last_update >= cutoff)
                break;
            map_.erase(found);
            order_.pop_back();
        }
    }

    std::size_t size() const { return map_.size(); }

    /// Number of live records dropped because the table was full (idle expiry is not counted).
    std::uint64_t capacity_evictions() const { return capacity_evictions_; }

private:
    // Drop the least advanced of the oldest few records.
    void evict_for_capacity() {
        auto victim = order_.end();
        std::size_t victim_progress = 0;
        std::size_t examined = 0;
        for (auto it = order_.rbegin(); it != order_.rend() && examined < kEvictionCandidates;
             ++it, ++examined) {
            const std::size_t progress = map_.find(*it)->second.record.progress();
            if (victim == order_.end() || progress < victim_progress) {
                victim = std::prev(it.base());
                victim_progress = progress;
            }
        }
        map_.erase(*victim);
        order_.erase(victim);
        ++capacity_evictions_;
    }

    struct Slot {
        Record record;
        TimePoint last_update;
        typename std::list<Key>::iterator position;
    };

    std::size_t max_entries_;
    std::uint64_t capacity_evictions_ = 0;
    std::list<Key> order_;  // most recently updated first
    std::unordered_map<Key, Slot> map_;
};

}  // namespace sf
