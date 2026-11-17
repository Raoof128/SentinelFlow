#include "sentinelflow/alert/alert_manager.hpp"

namespace sf {

void AlertManager::add_output(std::unique_ptr<AlertOutput> output) {
    outputs_.push_back(std::move(output));
}

void AlertManager::process(const Alert& alert) {
    ++total_alerts_;
    for (auto& output : outputs_) {
        output->emit(alert);
    }
}

void AlertManager::process(const std::vector<Alert>& alerts) {
    for (const auto& alert : alerts) {
        process(alert);
    }
}

}  // namespace sf
