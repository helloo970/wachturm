#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#endif

#include "net/HostDiscovery.hpp"

#include "core/Logger.hpp"
#include "net/Socket.hpp"
#include "net/Targets.hpp"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <fstream>
#include <future>
#include <sstream>

namespace wt::net {

std::optional<std::string> arpLookup(std::uint32_t ip) {
#ifdef _WIN32
    ULONG mac[2] = {0, 0};
    ULONG len = 6;
    // SendARP erwartet die IP in Netzwerk-Byte-Reihenfolge.
    const IPAddr dest = htonl(ip);
    if (SendARP(dest, 0, mac, &len) != NO_ERROR || len != 6) return std::nullopt;

    const auto* b = reinterpret_cast<const unsigned char*>(mac);
    char text[18];
    std::snprintf(text, sizeof(text), "%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5]);
    return std::string(text);
#else
    // Linux fuehrt die ARP-Tabelle in /proc/net/arp:
    //   IP address  HW type  Flags  HW address         Mask  Device
    //   192.168.1.1 0x1      0x2    aa:bb:cc:dd:ee:ff  *     eth0
    // Ein Eintrag existiert nur, wenn vorher Verkehr lief (macht der TCP-Sweep).
    std::ifstream in("/proc/net/arp");
    if (!in) return std::nullopt;
    const std::string wanted = ipv4ToString(ip);
    std::string line;
    std::getline(in, line);  // Ueberschrift
    while (std::getline(in, line)) {
        std::istringstream ls(line);
        std::string ipText, hwType, flags, mac;
        if (!(ls >> ipText >> hwType >> flags >> mac)) continue;
        // Flags 0x0 = unvollstaendig (Host hat nicht geantwortet)
        if (ipText == wanted && flags != "0x0" && mac != "00:00:00:00:00:00") return mac;
    }
    return std::nullopt;
#endif
}

std::optional<HostInfo> HostDiscovery::probeHost(std::uint32_t ip) const {
    const auto timeout = std::chrono::milliseconds(cfg_.connectTimeoutMs);
    HostInfo info;
    info.ip = ip;
    info.ipText = ipv4ToString(ip);

    if (auto hit = firstResponsivePort(ip, cfg_.discoveryPorts, timeout)) {
        info.method = "tcp/" + std::to_string(hit->port);
        info.rtt = hit->rtt;
        if (auto mac = arpLookup(ip)) info.mac = *mac;
    } else if (auto mac = arpLookup(ip)) {
        // Antwortet nicht auf TCP, ist aber per ARP da (z. B. Smartphone im Standby)
        info.mac = *mac;
        info.method = "arp";
    } else {
        return std::nullopt;
    }

    info.hostname = reverseLookup(ip);
    return info;
}

std::vector<HostInfo> HostDiscovery::run(const std::vector<std::uint32_t>& targets, const ProgressFn& progress) {
    logInfo("Host-Discovery: " + std::to_string(targets.size()) + " Adressen, " +
            std::to_string(pool_.size()) + " Threads");

    std::atomic<std::size_t> done{0};
    std::vector<std::future<std::optional<HostInfo>>> futures;
    futures.reserve(targets.size());

    for (const auto ip : targets) {
        futures.push_back(pool_.submit([this, ip, &done, &progress, total = targets.size()] {
            std::optional<HostInfo> r;
            try {
                r = probeHost(ip);
            } catch (const std::exception& e) {
                logWarn("Probe " + ipv4ToString(ip) + " fehlgeschlagen: " + e.what());
            }
            const auto n = ++done;
            if (progress) progress(n, total);
            return r;
        }));
    }

    std::vector<HostInfo> hosts;
    for (auto& f : futures) {
        if (auto h = f.get()) hosts.push_back(std::move(*h));
    }
    std::sort(hosts.begin(), hosts.end(), [](const HostInfo& a, const HostInfo& b) { return a.ip < b.ip; });
    logInfo("Host-Discovery fertig: " + std::to_string(hosts.size()) + " Geraete gefunden");
    return hosts;
}

}  // namespace wt::net
