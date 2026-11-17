#pragma once
#include "sentinelflow/alert/alert_manager.hpp"

namespace sf {

class ConsoleLogger : public AlertOutput {
public:
    void emit(const Alert& alert) override;
};

}  // namespace sf
