#include "sentinelflow/alert/csv_logger.hpp"
#include "sentinelflow/utils/timestamp.hpp"

namespace sf {

CsvLogger::CsvLogger(const std::string& filepath)
    : file_(filepath, std::ios::app) {
    if (file_.tellp() == 0) {
        file_ << "timestamp,severity,sid,src_ip,src_port,dst_ip,dst_port,message\n";
    }
}

CsvLogger::~CsvLogger() {
    if (file_.is_open()) file_.close();
}

void CsvLogger::emit(const Alert& alert) {
    file_ << format_timestamp(alert.timestamp) << ","
          << alert.severity_string() << ","
          << alert.sid << ","
          << ip_to_string(alert.src_ip) << ","
          << alert.src_port << ","
          << ip_to_string(alert.dst_ip) << ","
          << alert.dst_port << ","
          << "\"" << alert.message << "\""
          << "\n";
    file_.flush();
}

} // namespace sf
