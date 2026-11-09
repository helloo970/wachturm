#pragma once
// Plattformunabhaengige TCP-Probes (Winsock / POSIX).
// Alle IPv4-Adressen werden als uint32_t in HOST-Byte-Reihenfolge uebergeben
// (192.168.1.1 == 0xC0A80101).

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace wt::net {

// RAII: startet/beendet Winsock. Einmal in main() anlegen.
class NetworkSession {
public:
    NetworkSession();
    ~NetworkSession();
    NetworkSession(const NetworkSession&) = delete;
    NetworkSession& operator=(const NetworkSession&) = delete;
};

enum class PortState {
    Open,        // Verbindung aufgebaut
    Closed,      // RST erhalten -> Host lebt, Port zu
    Filtered,    // Keine Antwort (Firewall / Host aus)
    Unreachable  // Netzwerkfehler (Host/Netz nicht erreichbar)
};

std::string_view portStateName(PortState s);

struct ProbeResult {
    PortState state = PortState::Filtered;
    std::chrono::milliseconds rtt{0};
    std::string banner;  // leer, wenn kein Banner gelesen wurde
};

// Ein TCP-Connect auf ip:port mit Timeout. Optional wird danach ein Banner gelesen.
ProbeResult probeTcp(std::uint32_t ip, std::uint16_t port, std::chrono::milliseconds connectTimeout,
                     std::optional<std::chrono::milliseconds> bannerTimeout = std::nullopt);

// Startet Verbindungen zu VIELEN Ports gleichzeitig und wartet nur EINMAL.
// Liefert den ersten Port, der antwortet (Open oder Closed = Host lebt).
struct AliveHit {
    std::uint16_t port;
    PortState state;
    std::chrono::milliseconds rtt;
};
std::optional<AliveHit> firstResponsivePort(std::uint32_t ip, const std::vector<std::uint16_t>& ports,
                                            std::chrono::milliseconds timeout);

// "192.168.1.1" oder "router.fritz.box" -> IPv4
std::optional<std::uint32_t> resolveIpv4(const std::string& host);

// IPv4 -> Hostname (Reverse-DNS), leer wenn unbekannt
std::string reverseLookup(std::uint32_t ip);

}  // namespace wt::net
