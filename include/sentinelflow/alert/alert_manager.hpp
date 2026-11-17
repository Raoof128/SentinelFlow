#pragma once
#include <functional>
#include <memory>
#include <vector>

#include "sentinelflow/alert/alert.hpp"

namespace sf {

class AlertOutput {
public:
    virtual ~AlertOutput() = default;
    virtual void emit(const Alert& alert) = 0;
};

class AlertManager {
public:
    void add_output(std::unique_ptr<AlertOutput> output);
    void process(const Alert& alert);
    void process(const std::vector<Alert>& alerts);
    uint64_t total_alerts() const { return total_alerts_; }

private:
    std::vector<std::unique_ptr<AlertOutput>> outputs_;
    uint64_t total_alerts_ = 0;
};

}  // namespace sf
