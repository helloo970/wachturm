#pragma once
// Ergebnisse ausgeben: Konsole, JSON (maschinenlesbar), HTML.

#include "fim/Baseline.hpp"
#include "fim/Detector.hpp"
#include "net/HostDiscovery.hpp"
#include "net/PortScanner.hpp"
#include "net/ServiceAudit.hpp"

#include <filesystem>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <vector>

namespace wt::report {

struct NetworkReport {
    std::string target;
    std::vector<net::HostInfo> hosts;
    std::vector<net::HostScan> scans;
    std::vector<net::Finding> findings;
};

struct FileReport {
    std::string root;
    fim::SnapshotDiff diff;
    std::vector<fim::Verdict> verdicts;  // nur Dateien mit Score > 0
};

nlohmann::json toJson(const NetworkReport& r);
nlohmann::json toJson(const FileReport& r);

// Schreibt <dir>/<prefix>-<zeit>.json und gibt den Pfad zurueck.
std::filesystem::path writeJson(const nlohmann::json& j, const std::filesystem::path& dir, std::string_view prefix);

// HTML-Bericht (hell/dunkel, alle fremden Daten escaped). Gibt den Pfad zurueck.
std::filesystem::path writeHtml(const NetworkReport& r, const std::filesystem::path& dir);

void printHosts(const std::vector<net::HostInfo>& hosts);
void printScan(const net::HostScan& scan);
void printFindings(const std::vector<net::Finding>& findings);
void printFileReport(const FileReport& r, int threshold);

}  // namespace wt::report
