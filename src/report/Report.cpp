#include "report/Report.hpp"

#include "core/Console.hpp"
#include "core/Logger.hpp"
#include "core/Utf8.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace fs = std::filesystem;
using nlohmann::json;

namespace wt::report {
namespace {

// Text auf sichtbare Breite auffuellen bzw. mit "…" kuerzen (UTF-8/ANSI-bewusst)
std::string cell(const std::string& text, std::size_t width) {
    const std::size_t w = console::visibleWidth(text);
    if (w <= width) return text + std::string(width - w, ' ');
    // Kuerzen: Codepoints zaehlen, Folgebytes mitnehmen
    std::string out;
    std::size_t visible = 0;
    for (std::size_t i = 0; i < text.size(); ++i) {
        const auto c = static_cast<unsigned char>(text[i]);
        if ((c & 0xC0) != 0x80) {
            if (visible + 1 >= width) break;
            ++visible;
        }
        out.push_back(text[i]);
    }
    return out + "…" + std::string(width - visible - 1, ' ');
}

std::string orDash(const std::string& s) { return s.empty() ? "-" : s; }

std::string rule(std::size_t width) {
    std::string s;
    for (std::size_t i = 0; i < width; ++i) s += "─";
    return std::string(console::kGray) + s + std::string(console::kReset);
}

std::string header(const std::string& text) {
    return std::string(console::kBold) + text + std::string(console::kReset);
}

std::string scoreColor(int score, int threshold) {
    if (score >= threshold) return std::string(console::kRed);
    if (score >= threshold / 2) return std::string(console::kYellow);
    return std::string(console::kCyan);
}

std::string htmlEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default: out.push_back(c);
        }
    }
    return out;
}

std::string_view severityCss(net::Severity s) {
    switch (s) {
        case net::Severity::Critical: return "crit";
        case net::Severity::High: return "high";
        case net::Severity::Medium: return "med";
        case net::Severity::Low: return "low";
        default: return "info";
    }
}

}  // namespace

json toJson(const NetworkReport& r) {
    json j;
    j["type"] = "network";
    j["target"] = r.target;
    j["created"] = currentTimestamp();

    j["hosts"] = json::array();
    for (const auto& h : r.hosts) {
        j["hosts"].push_back({{"ip", h.ipText}, {"hostname", h.hostname}, {"mac", h.mac},
                              {"method", h.method}, {"rtt_ms", h.rtt.count()}});
    }
    j["scans"] = json::array();
    for (const auto& s : r.scans) {
        json ports = json::array();
        for (const auto& p : s.openPorts) {
            ports.push_back({{"port", p.port}, {"service", p.service}, {"banner", p.banner}, {"rtt_ms", p.rtt.count()}});
        }
        j["scans"].push_back({{"ip", s.ipText}, {"open", ports}, {"closed", s.closed}, {"filtered", s.filtered}});
    }
    j["findings"] = json::array();
    for (const auto& f : r.findings) {
        j["findings"].push_back({{"severity", std::string(net::severityName(f.severity))},
                                 {"severity_level", static_cast<int>(f.severity)},
                                 {"host", f.host}, {"port", f.port}, {"title", f.title}, {"advice", f.advice}});
    }
    return j;
}

json toJson(const FileReport& r) {
    json j;
    j["type"] = "files";
    j["root"] = r.root;
    j["created"] = currentTimestamp();
    j["added"] = r.diff.added;
    j["modified"] = r.diff.modified;
    j["removed"] = r.diff.removed;
    j["verdicts"] = json::array();
    for (const auto& v : r.verdicts) {
        j["verdicts"].push_back({{"path", v.path}, {"sha256", v.sha256}, {"score", v.score},
                                 {"entropy", v.entropy}, {"reasons", v.reasons}, {"quarantined", v.quarantined},
                                 {"quarantine_id", v.quarantineId}, {"protected_path", v.protectedPath}});
    }
    return j;
}

fs::path writeJson(const json& j, const fs::path& dir, std::string_view prefix) {
    fs::create_directories(dir);
    const auto secs = std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::system_clock::now().time_since_epoch()).count();
    const fs::path file = dir / (std::string(prefix) + "-" + std::to_string(secs) + ".json");
    std::ofstream out(file, std::ios::binary);
    if (!out) throw std::runtime_error("Bericht kann nicht geschrieben werden: " + pathToUtf8(file));
    out << j.dump(2);
    logInfo("Bericht gespeichert: " + pathToUtf8(file));
    return file;
}

fs::path writeHtml(const NetworkReport& r, const fs::path& dir) {
    fs::create_directories(dir);
    const auto secs = std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::system_clock::now().time_since_epoch()).count();
    const fs::path file = dir / ("audit-" + std::to_string(secs) + ".html");
    std::ofstream out(file, std::ios::binary);
    if (!out) throw std::runtime_error("HTML-Bericht kann nicht geschrieben werden: " + pathToUtf8(file));

    // Alles, was von fremden Geraeten kommt (Banner, Hostnamen), wird escaped -
    // sonst koennte ein Geraet JavaScript in den Bericht schmuggeln.
    out << "<!doctype html><html lang='de'><head><meta charset='utf-8'>"
           "<meta name='viewport' content='width=device-width,initial-scale=1'>"
           "<title>Wachturm-Bericht</title><style>"
           ":root{color-scheme:light dark;--bg:#f6f8fa;--fg:#1f2328;--card:#fff;--line:#d0d7de;--muted:#656d76}"
           "@media(prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--card:#161b22;--line:#30363d;--muted:#8b949e}}"
           "body{font-family:system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:24px;max-width:1100px;margin:auto}"
           "h1{margin:0 0 4px}.muted{color:var(--muted)}"
           ".card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px;margin:16px 0;overflow-x:auto}"
           "table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top}"
           "code{font-size:.9em;word-break:break-all}"
           ".sev{font-weight:600;padding:2px 8px;border-radius:12px;font-size:.85em;white-space:nowrap}"
           ".crit{background:#8250df;color:#fff}.high{background:#cf222e;color:#fff}.med{background:#d4a72c;color:#000}"
           ".low{background:#218bff;color:#fff}.info{background:#8c959f;color:#fff}"
           ".stats{display:flex;gap:24px;flex-wrap:wrap}.stats b{font-size:1.6em;display:block}"
           "</style></head><body>";

    out << "<h1>Wachturm-Bericht</h1><div class='muted'>Ziel: " << htmlEscape(r.target) << " &middot; erstellt "
        << htmlEscape(currentTimestamp()) << "</div>";

    std::size_t openPorts = 0;
    for (const auto& s : r.scans) openPorts += s.openPorts.size();
    const auto serious = std::count_if(r.findings.begin(), r.findings.end(),
                                       [](const net::Finding& f) { return f.severity >= net::Severity::High; });
    out << "<div class='card stats'><div><b>" << r.hosts.size() << "</b>Geräte</div><div><b>" << openPorts
        << "</b>offene Ports</div><div><b>" << r.findings.size() << "</b>Funde</div><div><b>" << serious
        << "</b>hoch/kritisch</div></div>";

    out << "<div class='card'><h2>Funde</h2>";
    if (r.findings.empty()) {
        out << "<p>Keine unsicheren Dienste gefunden.</p>";
    } else {
        out << "<table><tr><th>Schwere</th><th>Host</th><th>Port</th><th>Problem</th><th>Empfehlung</th></tr>";
        for (const auto& f : r.findings) {
            out << "<tr><td><span class='sev " << severityCss(f.severity) << "'>"
                << htmlEscape(std::string(net::severityName(f.severity))) << "</span></td><td>" << htmlEscape(f.host)
                << "</td><td>" << f.port << "</td><td>" << htmlEscape(f.title) << "</td><td>" << htmlEscape(f.advice)
                << "</td></tr>";
        }
        out << "</table>";
    }
    out << "</div>";

    out << "<div class='card'><h2>Geräte</h2><table><tr><th>IP</th><th>Hostname</th><th>MAC</th><th>Gefunden über</th></tr>";
    for (const auto& h : r.hosts) {
        out << "<tr><td>" << htmlEscape(h.ipText) << "</td><td>" << htmlEscape(orDash(h.hostname)) << "</td><td><code>"
            << htmlEscape(orDash(h.mac)) << "</code></td><td>" << htmlEscape(h.method) << "</td></tr>";
    }
    out << "</table></div>";

    for (const auto& s : r.scans) {
        out << "<div class='card'><h2>" << htmlEscape(s.ipText) << "</h2><div class='muted'>" << s.openPorts.size()
            << " offen &middot; " << s.closed << " geschlossen &middot; " << s.filtered << " gefiltert</div>";
        if (!s.openPorts.empty()) {
            out << "<table><tr><th>Port</th><th>Dienst</th><th>Banner</th></tr>";
            for (const auto& p : s.openPorts) {
                out << "<tr><td>" << p.port << "/tcp</td><td>" << htmlEscape(orDash(p.service)) << "</td><td><code>"
                    << htmlEscape(orDash(p.banner)) << "</code></td></tr>";
            }
            out << "</table>";
        }
        out << "</div>";
    }
    out << "</body></html>\n";

    logInfo("HTML-Bericht gespeichert: " + pathToUtf8(file));
    return file;
}

void printHosts(const std::vector<net::HostInfo>& hosts) {
    std::cout << "\n" << header("Gefundene Geräte: " + std::to_string(hosts.size())) << "\n";
    if (hosts.empty()) return;
    std::cout << "  " << header(cell("IP", 16) + cell("MAC", 19) + cell("Über", 11) + cell("Antwort", 9) + "Hostname")
              << "\n  " << rule(75) << "\n";
    for (const auto& h : hosts) {
        const std::string rtt = h.method == "arp" ? "-" : std::to_string(h.rtt.count()) + " ms";
        std::cout << "  " << console::kGreen << cell(h.ipText, 16) << console::kReset << cell(orDash(h.mac), 19)
                  << cell(h.method, 11) << cell(rtt, 9) << orDash(h.hostname) << "\n";
    }
}

void printScan(const net::HostScan& scan) {
    std::cout << "\n" << header(scan.ipText) << console::kGray << "   offen: " << scan.openPorts.size()
              << "  geschlossen: " << scan.closed << "  gefiltert: " << scan.filtered << console::kReset << "\n";
    if (scan.openPorts.empty()) return;
    std::cout << "  " << header(cell("Port", 10) + cell("Dienst", 16) + "Banner") << "\n  " << rule(75) << "\n";
    for (const auto& p : scan.openPorts) {
        std::cout << "  " << console::kGreen << cell(std::to_string(p.port) + "/tcp", 10) << console::kReset
                  << cell(orDash(p.service), 16) << console::kGray << cell(orDash(p.banner), 60) << console::kReset
                  << "\n";
    }
}

void printFindings(const std::vector<net::Finding>& findings) {
    if (findings.empty()) {
        std::cout << console::kGreen << "\n✔ Keine unsicheren Dienste gefunden.\n" << console::kReset;
        return;
    }
    std::cout << "\n" << header("Funde (" + std::to_string(findings.size()) + "):") << "\n";
    for (const auto& f : findings) {
        std::cout << "  " << net::severityColor(f.severity) << cell("[" + std::string(net::severityName(f.severity)) + "]", 11)
                  << console::kReset << cell(f.host + ":" + std::to_string(f.port), 22) << f.title << "\n"
                  << console::kGray << "             → " << f.advice << console::kReset << "\n";
    }
}

void printFileReport(const FileReport& r, int threshold) {
    std::cout << "\n" << header("Ordner: " + r.root) << "\n"
              << "  " << console::kGreen << "+" << r.diff.added.size() << " neu" << console::kReset << "   "
              << console::kYellow << "~" << r.diff.modified.size() << " geändert" << console::kReset << "   "
              << console::kRed << "-" << r.diff.removed.size() << " gelöscht" << console::kReset << "\n";

    // Geloeschte Dateien koennen auch ein Warnsignal sein (z. B. Logs geloescht)
    const std::size_t shown = std::min<std::size_t>(r.diff.removed.size(), 10);
    for (std::size_t i = 0; i < shown; ++i) std::cout << console::kGray << "    - " << r.diff.removed[i] << console::kReset << "\n";
    if (r.diff.removed.size() > shown) std::cout << console::kGray << "    … und " << r.diff.removed.size() - shown << " weitere\n" << console::kReset;

    if (r.verdicts.empty()) {
        std::cout << console::kGreen << "\n✔ Nichts Auffälliges gefunden.\n" << console::kReset;
        return;
    }

    int malicious = 0, quarantined = 0;
    std::cout << "\n" << header("Auffällige Dateien:") << "\n";
    for (const auto& v : r.verdicts) {
        if (v.score >= threshold) ++malicious;
        if (v.quarantined) ++quarantined;
        char entropy[16];
        std::snprintf(entropy, sizeof(entropy), "%.2f", v.entropy);
        std::cout << "  " << scoreColor(v.score, threshold) << cell("[" + std::to_string(v.score) + "]", 7)
                  << console::kReset << v.path << console::kGray << "  (Entropie " << entropy << ")" << console::kReset;
        if (v.quarantined) std::cout << console::kMagenta << "  → Quarantäne " << v.quarantineId << console::kReset;
        else if (v.score >= threshold && v.protectedPath) std::cout << console::kYellow << "  (Systempfad, nicht verschoben)" << console::kReset;
        std::cout << "\n";
        for (const auto& reason : v.reasons) std::cout << console::kGray << "         • " << reason << console::kReset << "\n";
    }

    std::cout << "\n" << header("Zusammenfassung: ") << r.verdicts.size() << " auffällig, "
              << (malicious > 0 ? console::kRed : console::kGreen) << malicious << " schädlich" << console::kReset
              << ", " << quarantined << " in Quarantäne\n";
}

}  // namespace wt::report
