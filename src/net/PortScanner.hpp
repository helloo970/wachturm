#pragma once
// TCP-Connect-Portscanner mit Banner-Grabbing.

#include "core/Config.hpp"
#include "core/ThreadPool.hpp"
#include "net/Socket.hpp"

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace wt::net {

struct PortResult {
    std::uint16_t port = 0;
    PortState state = PortState::Filtered;
    std::string service;  // "ssh", "http" ...
    std::string banner;
    std::chrono::milliseconds rtt{0};
};

struct HostScan {
    std::uint32_t ip = 0;
    std::string ipText;
    std::vector<PortResult> openPorts;  // nur offene Ports, sortiert
    std::size_t closed = 0;
    std::size_t filtered = 0;
};

class PortScanner {
public:
    PortScanner(const Config& cfg, ThreadPool& pool) : cfg_(cfg), pool_(pool) {}

    HostScan scan(std::uint32_t ip, const std::vector<std::uint16_t>& ports, const ProgressFn& progress = {});

private:
    const Config& cfg_;
    ThreadPool& pool_;
};

// Bekannter Dienstname zu einem Port, "" wenn unbekannt.
std::string_view serviceName(std::uint16_t port);

}  // namespace wt::net
