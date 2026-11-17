#pragma once
#include <fstream>
#include <string>

#include "sentinelflow/alert/alert_manager.hpp"

namespace sf {

class CsvLogger : public AlertOutput {
public:
    explicit CsvLogger(const std::string& filepath);
    ~CsvLogger() override;

    void emit(const Alert& alert) override;

private:
    std::ofstream file_;
};

}  // namespace sf
