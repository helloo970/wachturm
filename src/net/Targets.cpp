#include "net/Targets.hpp"

#include "net/Socket.hpp"

#include <algorithm>
#include <charconv>
#include <stdexcept>
#include <unordered_set>

namespace wt::net {
namespace {

std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
    return s;
}

std::vector<std::string_view> split(std::string_view s, char sep) {
    std::vector<std::string_view> parts;
    std::size_t start = 0;
    while (true) {
        const auto pos = s.find(sep, start);
        parts.push_back(trim(s.substr(start, pos - start)));
        if (pos == std::string_view::npos) break;
        start = pos + 1;
    }
    return parts;
}

// Ganze Zahl ohne Vorzeichen, nur Ziffern, im Bereich [lo, hi].
std::optional<unsigned> parseUnsigned(std::string_view s, unsigned lo, unsigned hi) {
    if (s.empty() || s.size() > 5) return std::nullopt;
    unsigned value = 0;
    const auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), value);
    if (ec != std::errc{} || ptr != s.data() + s.size()) return std::nullopt;
    if (value < lo || value > hi) return std::nullopt;
    return value;
}

void appendRange(std::vector<std::uint32_t>& out, std::unordered_set<std::uint32_t>& seen,
                 std::uint32_t first, std::uint32_t last, std::size_t maxHosts) {
    const std::uint64_t count = static_cast<std::uint64_t>(last) - first + 1;
    if (out.size() + count > maxHosts) {
        throw std::invalid_argument("Zu viele Ziele (max. " + std::to_string(maxHosts) + ")");
    }
    // uint64 als Schleifenvariable, damit 255.255.255.255 nicht ueberlaeuft
    for (std::uint64_t ip = first; ip <= last; ++ip) {
        const auto v = static_cast<std::uint32_t>(ip);
        if (seen.insert(v).second) out.push_back(v);
    }
}

}  // namespace

std::optional<std::uint32_t> parseIpv4(std::string_view text) {
    const auto parts = split(trim(text), '.');
    if (parts.size() != 4) return std::nullopt;
    std::uint32_t ip = 0;
    for (auto part : parts) {
        if (part.size() > 3) return std::nullopt;
        auto octet = parseUnsigned(part, 0, 255);
        if (!octet) return std::nullopt;
        ip = (ip << 8) | *octet;
    }
    return ip;
}

std::string ipv4ToString(std::uint32_t ip) {
    return std::to_string((ip >> 24) & 0xFF) + '.' + std::to_string((ip >> 16) & 0xFF) + '.' +
           std::to_string((ip >> 8) & 0xFF) + '.' + std::to_string(ip & 0xFF);
}

std::vector<std::uint32_t> expandTargets(std::string_view spec, std::size_t maxHosts) {
    std::vector<std::uint32_t> result;
    std::unordered_set<std::uint32_t> seen;

    for (auto part : split(spec, ',')) {
        if (part.empty()) continue;

        // --- CIDR: a.b.c.d/nn ---
        if (const auto slash = part.find('/'); slash != std::string_view::npos) {
            const auto base = parseIpv4(part.substr(0, slash));
            const auto prefix = parseUnsigned(part.substr(slash + 1), 0, 32);
            if (!base || !prefix) {
                throw std::invalid_argument("Ungueltiges Netz: " + std::string(part));
            }
            const std::uint32_t mask = (*prefix == 0) ? 0u : (~0u << (32 - *prefix));
            const std::uint32_t network = *base & mask;
            const std::uint32_t broadcast = network | ~mask;
            if (*prefix >= 31) {
                // /31 (Punkt-zu-Punkt) und /32 haben keine Netz-/Broadcast-Adresse
                appendRange(result, seen, network, broadcast, maxHosts);
            } else {
                appendRange(result, seen, network + 1, broadcast - 1, maxHosts);
            }
            continue;
        }

        // --- Bereich: a.b.c.d-e  oder  a.b.c.d-a.b.c.e ---
        if (const auto dash = part.find('-'); dash != std::string_view::npos && parseIpv4(part.substr(0, dash))) {
            const std::uint32_t first = *parseIpv4(part.substr(0, dash));
            const auto rhs = part.substr(dash + 1);
            std::uint32_t last = 0;
            if (rhs.find('.') != std::string_view::npos) {
                const auto full = parseIpv4(rhs);
                if (!full) throw std::invalid_argument("Ungueltiger Bereich: " + std::string(part));
                last = *full;
            } else {
                const auto octet = parseUnsigned(rhs, 0, 255);
                if (!octet) throw std::invalid_argument("Ungueltiger Bereich: " + std::string(part));
                last = (first & 0xFFFFFF00u) | *octet;
            }
            if (last < first) throw std::invalid_argument("Bereich ist rueckwaerts: " + std::string(part));
            appendRange(result, seen, first, last, maxHosts);
            continue;
        }

        // --- Einzelne IP oder Hostname ---
        if (const auto ip = parseIpv4(part)) {
            appendRange(result, seen, *ip, *ip, maxHosts);
        } else if (const auto resolved = resolveIpv4(std::string(part))) {
            appendRange(result, seen, *resolved, *resolved, maxHosts);
        } else {
            throw std::invalid_argument("Host nicht aufloesbar: " + std::string(part));
        }
    }

    if (result.empty()) throw std::invalid_argument("Kein Ziel angegeben");
    return result;
}

std::vector<std::uint16_t> parsePortSpec(std::string_view spec) {
    std::vector<std::uint16_t> ports;
    for (auto part : split(spec, ',')) {
        if (part.empty()) continue;
        const auto dash = part.find('-');
        if (dash == std::string_view::npos) {
            const auto p = parseUnsigned(part, 1, 65535);
            if (!p) throw std::invalid_argument("Ungueltiger Port: " + std::string(part));
            ports.push_back(static_cast<std::uint16_t>(*p));
            continue;
        }
        const auto lo = parseUnsigned(trim(part.substr(0, dash)), 1, 65535);
        const auto hi = parseUnsigned(trim(part.substr(dash + 1)), 1, 65535);
        if (!lo || !hi || *lo > *hi) {
            throw std::invalid_argument("Ungueltiger Portbereich: " + std::string(part));
        }
        for (unsigned p = *lo; p <= *hi; ++p) ports.push_back(static_cast<std::uint16_t>(p));
    }
    std::sort(ports.begin(), ports.end());
    ports.erase(std::unique(ports.begin(), ports.end()), ports.end());
    if (ports.empty()) throw std::invalid_argument("Keine Ports angegeben");
    return ports;
}

}  // namespace wt::net
