#pragma once
// Bewertet offene Ports und Banner: unsichere Dienste, alte Versionen ...

#include "net/PortScanner.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace wt::net {

enum class Severity { Info, Low, Medium, High, Critical };

struct Finding {
    Severity severity = Severity::Info;
    std::string host;
    std::uint16_t port = 0;
    std::string title;
    std::string advice;
};

std::vector<Finding> auditHost(const HostScan& scan);

std::string_view severityName(Severity s);   // "KRITISCH", "HOCH" ...
std::string_view severityColor(Severity s);  // ANSI-Farbe

}  // namespace wt::net
