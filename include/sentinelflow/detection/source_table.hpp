#pragma once
#include <chrono>
#include <cstddef>
#include <list>
#include <unordered_map>

namespace sf {

/// Default cap on the number of sources (or source/destination pairs) a stateful detector tracks
/// at once. When the cap is reached the entry that was updated longest ago is dropped to make
/// room, so a stream of spoofed addresses cannot grow memory without bound.
///
/// Worst-case memory is this many entries times the per-entry state, which each detector keeps
/// to O(threshold). Every detector takes the cap as a constructor argument.
constexpr std::size_t kDefaultMaxTrackedSources = 65536;

/// Per-key detector state with a bounded size.
///
/// Records are kept in the order they were last updated, most recent first. That order serves
/// two purposes:
///   - evict_idle() drops records not updated since a cutoff time by looking only at the cold
///     end of the list, so each record is examined once on its way out and the cost per packet is
///     amortised constant;
///   - touch() drops the least recently updated record when the table is full.
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
        if (map_.size() >= max_entries_) {
            map_.erase(order_.back());
            order_.pop_back();
        }
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

private:
    struct Slot {
        Record record;
        TimePoint last_update;
        typename std::list<Key>::iterator position;
    };

    std::size_t max_entries_;
    std::list<Key> order_;  // most recently updated first
    std::unordered_map<Key, Slot> map_;
};

}  // namespace sf
