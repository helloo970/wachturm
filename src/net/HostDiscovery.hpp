#pragma once
// Findet Geraete im (Heim-)Netz.
//  1. TCP-Sweep: viele Ports gleichzeitig anklopfen, jede Antwort (auch RST) = Host lebt.
//  2. Windows: zusaetzlich ARP (SendARP) - findet auch Handys/IoT, die TCP ignorieren.
//     Linux: ARP-Tabelle /proc/net/arp lesen.

#include "core/Config.hpp"
#include "core/ThreadPool.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace wt::net {

struct HostInfo {
    std::uint32_t ip = 0;
    std::string ipText;
    std::string hostname;  // per Reverse-DNS
    std::string mac;       // "aa:bb:cc:dd:ee:ff", leer wenn unbekannt
    std::string method;    // "tcp/443" oder "arp"
    std::chrono::milliseconds rtt{0};
};

class HostDiscovery {
public:
    HostDiscovery(const Config& cfg, ThreadPool& pool) : cfg_(cfg), pool_(pool) {}

    // Ergebnis ist nach IP sortiert.
    std::vector<HostInfo> run(const std::vector<std::uint32_t>& targets, const ProgressFn& progress = {});

private:
    std::optional<HostInfo> probeHost(std::uint32_t ip) const;

    const Config& cfg_;
    ThreadPool& pool_;
};

// MAC-Adresse per ARP (nur im lokalen Subnetz moeglich).
std::optional<std::string> arpLookup(std::uint32_t ip);

}  // namespace wt::net
