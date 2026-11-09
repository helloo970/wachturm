#pragma once
// Ziel- und Portangaben parsen:
//   "192.168.178.0/24"          CIDR-Netz
//   "192.168.178.10-50"         Bereich im letzten Oktett
//   "192.168.178.10-192.168.178.20"
//   "fritz.box"                 Hostname
//   mehrere mit Komma getrennt
// Ports: "22,80,443,8000-8100"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace wt::net {

std::optional<std::uint32_t> parseIpv4(std::string_view text);
std::string ipv4ToString(std::uint32_t ip);

// Wirft std::invalid_argument bei Fehlern oder wenn mehr als maxHosts entstehen.
std::vector<std::uint32_t> expandTargets(std::string_view spec, std::size_t maxHosts = 65536);

// Wirft std::invalid_argument bei Fehlern. Ergebnis ist sortiert und ohne Duplikate.
std::vector<std::uint16_t> parsePortSpec(std::string_view spec);

}  // namespace wt::net
