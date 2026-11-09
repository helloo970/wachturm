// Wachturm - Heimnetz-Sicherheits-Suite
//
//   wachturm                         Intro + Hilfe
//   wachturm discover <netz>         Geraete finden          (192.168.178.0/24)
//   wachturm scan <host> [--ports]   Ports eines Geraets
//   wachturm audit <netz> [--ports]  discover + scan + Bewertung + Bericht
//   wachturm baseline <ordner>       Datei-Fingerabdruck speichern
//   wachturm check [ordner]          Vergleich + Malware-Erkennung + Quarantaene
//   wachturm quarantine list|restore <id>|delete <id>
//
// Globale Optionen: --config <datei>  --no-intro  --verbose  --json

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#endif

#include "core/Config.hpp"
#include "core/Console.hpp"
#include "core/Logger.hpp"
#include "core/ThreadPool.hpp"
#include "core/Utf8.hpp"
#include "fim/Baseline.hpp"
#include "fim/Detector.hpp"
#include "net/HostDiscovery.hpp"
#include "net/PortScanner.hpp"
#include "net/ServiceAudit.hpp"
#include "net/Socket.hpp"
#include "net/Targets.hpp"
#include "quarantine/Quarantine.hpp"
#include "report/Report.hpp"
#include "ui/Banner.hpp"
#include "ui/Progress.hpp"

#include <algorithm>
#include <cstdio>
#include <future>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace wt;

namespace {

// Exit-Codes
constexpr int kOk = 0;
constexpr int kError = 1;
constexpr int kFindings = 2;  // Erfolgreich gelaufen, aber Probleme gefunden

// ---------------------------------------------------------------------------
// Argumente
// ---------------------------------------------------------------------------
struct Args {
    std::string command;
    std::vector<std::string> positional;
    std::map<std::string, std::string> options;
    std::set<std::string> flags;

    bool has(const std::string& flag) const { return flags.count(flag) > 0; }
    std::optional<std::string> opt(const std::string& name) const {
        auto it = options.find(name);
        return it == options.end() ? std::nullopt : std::optional(it->second);
    }
    const std::string& require(std::size_t index, const char* what) const {
        if (index >= positional.size()) throw std::invalid_argument(std::string("Fehlt: ") + what);
        return positional[index];
    }
};

// Unter Windows kommen argv-Strings in der ANSI-Codepage -> Umlaute in Pfaden
// gehen kaputt. Darum die Unicode-Kommandozeile holen und nach UTF-8 wandeln.
std::vector<std::string> utf8Arguments(int argc, char** argv) {
    std::vector<std::string> out;
#ifdef _WIN32
    (void)argc;
    (void)argv;
    int count = 0;
    LPWSTR* wargv = CommandLineToArgvW(GetCommandLineW(), &count);
    if (wargv) {
        for (int i = 0; i < count; ++i) {
            const int len = WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, nullptr, 0, nullptr, nullptr);
            std::string s(static_cast<std::size_t>(std::max(0, len - 1)), '\0');
            if (len > 1) WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, s.data(), len, nullptr, nullptr);
            out.push_back(std::move(s));
        }
        LocalFree(wargv);
        return out;
    }
#endif
    for (int i = 0; i < argc; ++i) out.emplace_back(argv[i]);
    return out;
}

Args parseArgs(const std::vector<std::string>& argv) {
    static const std::set<std::string> kValueOptions{"--config", "--ports", "--baseline", "--to"};
    Args a;
    for (std::size_t i = 1; i < argv.size(); ++i) {
        const std::string& s = argv[i];
        if (s.rfind("--", 0) == 0) {
            if (const auto eq = s.find('='); eq != std::string::npos) {
                a.options[s.substr(0, eq)] = s.substr(eq + 1);
            } else if (kValueOptions.count(s)) {
                if (i + 1 >= argv.size()) throw std::invalid_argument(s + " braucht einen Wert");
                a.options[s] = argv[++i];
            } else {
                a.flags.insert(s);
            }
        } else if (s == "-h" || s == "-?") {
            a.flags.insert("--help");
        } else if (s == "-v") {
            a.flags.insert("--verbose");
        } else if (s == "-j") {
            a.flags.insert("--json");
        } else if (s == "-f") {
            a.flags.insert("--force");
        } else if (s == "-p" || s == "-c" || s == "-b") {
            const std::string longName = s == "-p" ? "--ports" : s == "-c" ? "--config" : "--baseline";
            if (i + 1 >= argv.size()) throw std::invalid_argument(s + " braucht einen Wert");
            a.options[longName] = argv[++i];
        } else if (a.command.empty()) {
            a.command = s;
        } else {
            a.positional.push_back(s);
        }
    }
    return a;
}

void printHelp() {
    using namespace console;
    auto section = [](const char* title) { std::cout << "\n" << kBold << kCyan << title << kReset << "\n"; };
    auto item = [](const char* cmd, const char* desc) {
        std::cout << "  " << kGreen << cmd << kReset;
        const std::size_t w = visibleWidth(cmd);
        std::cout << std::string(w < 34 ? 34 - w : 1, ' ') << desc << "\n";
    };

    std::cout << kBold << "Wachturm " WT_VERSION << kReset << " - Sicherheits-Suite fürs Heimnetz\n"
              << kGray << "Aufruf: wachturm <befehl> [argumente] [optionen]" << kReset << "\n";

    section("Netzwerk");
    item("discover <netz>", "Geräte im Netz finden");
    item("scan <host>", "Ports eines Geräts prüfen");
    item("audit <netz>", "discover + scan + Bewertung + Bericht");

    section("Dateien");
    item("baseline <ordner>", "Fingerabdruck (SHA-256) aller Dateien speichern");
    item("check [ordner]", "Mit Baseline vergleichen, Malware suchen");

    section("Quarantäne");
    item("quarantine list", "Alle Einträge anzeigen");
    item("quarantine restore <id>", "Datei wiederherstellen");
    item("quarantine delete <id>", "Eintrag endgültig löschen");

    section("Optionen");
    item("-p, --ports <liste>", "Ports, z. B. 22,80,443,8000-8100");
    item("-j, --json", "JSON-Bericht in den report-Ordner schreiben");
    item("--html", "HTML-Bericht (nur audit)");
    item("--full", "check: ALLE Dateien analysieren, nicht nur neue");
    item("--update", "check: Baseline danach aktualisieren");
    item("--no-quarantine", "check: nur melden, nichts verschieben");
    item("-b, --baseline <datei>", "andere Baseline-Datei benutzen");
    item("--to <pfad>", "restore: an anderen Ort wiederherstellen");
    item("-f, --force", "restore: vorhandene Datei überschreiben");
    item("-c, --config <datei>", "andere Konfigurationsdatei");
    item("-v, --verbose", "ausführliche Ausgabe");
    item("--no-intro", "Logo-Animation überspringen");
    item("-h, --help", "diese Hilfe");

    section("Beispiele");
    std::cout << kGray
              << "  wachturm audit 192.168.178.0/24 --html\n"
              << "  wachturm scan fritz.box -p 1-65535\n"
              << "  wachturm baseline C:\\Users\\du\\Downloads\n"
              << "  wachturm check --update\n"
              << kReset
              << "\n" << kGray << "Exit-Codes: 0 = ok, 1 = Fehler, 2 = Probleme gefunden" << kReset << "\n";
}

std::string humanSize(std::uint64_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB"};
    double value = static_cast<double>(bytes);
    int unit = 0;
    while (value >= 1024.0 && unit < 3) { value /= 1024.0; ++unit; }
    char buf[32];
    std::snprintf(buf, sizeof(buf), unit == 0 ? "%.0f %s" : "%.1f %s", value, units[unit]);
    return buf;
}

bool progressEnabled() { return console::isTerminal(); }

// ---------------------------------------------------------------------------
// Netzwerk-Befehle
// ---------------------------------------------------------------------------
std::vector<net::HostInfo> runDiscovery(const Config& cfg, ThreadPool& pool, const std::string& target) {
    const auto targets = net::expandTargets(target);
    auto bar = std::make_shared<ui::ProgressBar>("Discovery", progressEnabled());
    net::HostDiscovery discovery(cfg, pool);
    auto hosts = discovery.run(targets, ui::ProgressBar::callback(bar));
    bar->finish();
    return hosts;
}

net::HostScan runPortScan(const Config& cfg, ThreadPool& pool, std::uint32_t ip, const std::vector<std::uint16_t>& ports) {
    auto bar = std::make_shared<ui::ProgressBar>("Portscan " + net::ipv4ToString(ip), progressEnabled());
    net::PortScanner scanner(cfg, pool);
    auto result = scanner.scan(ip, ports, ui::ProgressBar::callback(bar));
    bar->finish();
    return result;
}

int cmdDiscover(const Config& cfg, const Args& args) {
    net::NetworkSession session;
    ThreadPool pool(static_cast<std::size_t>(cfg.threads));
    report::NetworkReport rep;
    rep.target = args.require(0, "Netz, z. B. 192.168.178.0/24");
    rep.hosts = runDiscovery(cfg, pool, rep.target);
    report::printHosts(rep.hosts);
    if (args.has("--json")) report::writeJson(report::toJson(rep), cfg.reportDir, "discover");
    return kOk;
}

int cmdScan(const Config& cfg, const Args& args) {
    net::NetworkSession session;
    ThreadPool pool(static_cast<std::size_t>(cfg.threads));
    const std::string host = args.require(0, "Host, z. B. 192.168.178.1");
    const auto ip = net::resolveIpv4(host);
    if (!ip) throw std::invalid_argument("Host nicht aufloesbar: " + host);
    const auto ports = net::parsePortSpec(args.opt("--ports").value_or(cfg.defaultPorts));

    report::NetworkReport rep;
    rep.target = host;
    rep.scans.push_back(runPortScan(cfg, pool, *ip, ports));
    rep.findings = net::auditHost(rep.scans.back());
    report::printScan(rep.scans.back());
    report::printFindings(rep.findings);
    if (args.has("--json")) report::writeJson(report::toJson(rep), cfg.reportDir, "scan");
    return rep.findings.empty() ? kOk : kFindings;
}

int cmdAudit(const Config& cfg, const Args& args) {
    net::NetworkSession session;
    ThreadPool pool(static_cast<std::size_t>(cfg.threads));
    report::NetworkReport rep;
    rep.target = args.require(0, "Netz, z. B. 192.168.178.0/24");
    const auto ports = net::parsePortSpec(args.opt("--ports").value_or(cfg.defaultPorts));

    rep.hosts = runDiscovery(cfg, pool, rep.target);
    report::printHosts(rep.hosts);

    // Hosts NACHEINANDER, Ports eines Hosts parallel (siehe ThreadPool.hpp: kein Warten im Worker)
    for (const auto& h : rep.hosts) {
        rep.scans.push_back(runPortScan(cfg, pool, h.ip, ports));
        report::printScan(rep.scans.back());
        auto f = net::auditHost(rep.scans.back());
        rep.findings.insert(rep.findings.end(), f.begin(), f.end());
    }
    std::stable_sort(rep.findings.begin(), rep.findings.end(),
                     [](const net::Finding& a, const net::Finding& b) { return a.severity > b.severity; });
    report::printFindings(rep.findings);

    // Audit schreibt immer einen JSON-Bericht
    report::writeJson(report::toJson(rep), cfg.reportDir, "audit");
    if (args.has("--html")) {
        const auto html = report::writeHtml(rep, cfg.reportDir);
        std::cout << console::kGreen << "HTML-Bericht: " << pathToUtf8(fs::absolute(html)) << console::kReset << "\n";
    }

    const bool serious = std::any_of(rep.findings.begin(), rep.findings.end(),
                                     [](const net::Finding& f) { return f.severity >= net::Severity::High; });
    return serious ? kFindings : kOk;
}

// ---------------------------------------------------------------------------
// Datei-Befehle
// ---------------------------------------------------------------------------
fs::path baselineFile(const Config& cfg, const Args& args) {
    if (auto b = args.opt("--baseline")) return pathFromUtf8(*b);
    return cfg.baselineFile;
}

int cmdBaseline(const Config& cfg, const Args& args) {
    const fs::path root = pathFromUtf8(args.require(0, "Ordner"));
    ThreadPool pool(static_cast<std::size_t>(cfg.threads));
    auto bar = std::make_shared<ui::ProgressBar>("Hashing", progressEnabled());
    const auto snap = fim::buildSnapshot(root, cfg, pool, ui::ProgressBar::callback(bar));
    bar->finish();
    const fs::path file = baselineFile(cfg, args);
    fim::saveSnapshot(snap, root, file);
    std::cout << console::kGreen << "Baseline gespeichert: " << snap.size() << " Dateien -> " << pathToUtf8(file)
              << console::kReset << "\n";
    return kOk;
}

int cmdCheck(const Config& cfg, const Args& args) {
    const fs::path file = baselineFile(cfg, args);
    fs::path root;
    const fim::Snapshot before = fim::loadSnapshot(file, &root);

    if (!args.positional.empty()) {
        const fs::path given = fs::weakly_canonical(fs::absolute(pathFromUtf8(args.positional[0])));
        if (given != fs::weakly_canonical(root)) {
            throw std::invalid_argument("Die Baseline gehoert zu " + pathToUtf8(root) +
                                        " - fuer einen anderen Ordner --baseline <datei> angeben.");
        }
    }

    ThreadPool pool(static_cast<std::size_t>(cfg.threads));
    auto bar = std::make_shared<ui::ProgressBar>("Hashing", progressEnabled());
    fim::Snapshot after = fim::buildSnapshot(root, cfg, pool, ui::ProgressBar::callback(bar));
    bar->finish();

    report::FileReport rep;
    rep.root = pathToUtf8(root);
    rep.diff = fim::diffSnapshots(before, after);

    // Was wird untersucht? Standard: neue + geaenderte Dateien. --full: alle.
    std::set<std::string> changed(rep.diff.added.begin(), rep.diff.added.end());
    changed.insert(rep.diff.modified.begin(), rep.diff.modified.end());
    std::vector<std::string> toCheck;
    if (args.has("--full")) {
        for (const auto& [path, rec] : after) toCheck.push_back(path);
    } else {
        toCheck.assign(changed.begin(), changed.end());
    }

    fim::Detector detector(cfg);
    auto evalBar = std::make_shared<ui::ProgressBar>("Analyse", progressEnabled());
    std::vector<std::future<fim::Verdict>> futures;
    futures.reserve(toCheck.size());
    for (const auto& path : toCheck) {
        futures.push_back(pool.submit([&, path] {
            return detector.evaluate(pathFromUtf8(path), after.at(path).sha256, changed.count(path) > 0);
        }));
    }
    for (std::size_t i = 0; i < futures.size(); ++i) {
        fim::Verdict v = futures[i].get();
        evalBar->update(i + 1, futures.size());
        if (v.score > 0) rep.verdicts.push_back(std::move(v));
    }
    evalBar->finish();
    std::sort(rep.verdicts.begin(), rep.verdicts.end(),
              [](const fim::Verdict& a, const fim::Verdict& b) { return a.score > b.score; });

    // Quarantaene (nacheinander, nie parallel)
    const bool quarantineAllowed = cfg.autoQuarantine && !args.has("--no-quarantine");
    std::optional<Quarantine> quarantine;
    int malicious = 0;
    for (auto& v : rep.verdicts) {
        if (!detector.isMalicious(v)) continue;
        ++malicious;
        if (v.protectedPath) {
            logWarn("Verdaechtig, aber Systempfad - NICHT verschoben: " + v.path);
            continue;
        }
        if (!quarantineAllowed) {
            logWarn("Verdaechtig (Quarantaene deaktiviert): " + v.path);
            continue;
        }
        try {
            if (!quarantine) quarantine.emplace(cfg.quarantineDir, cfg.maxFileBytes);
            std::string reason;
            for (const auto& r : v.reasons) reason += (reason.empty() ? "" : "; ") + r;
            const auto entry = quarantine->isolate(pathFromUtf8(v.path), reason);
            v.quarantined = true;
            v.quarantineId = entry.id;
            after.erase(v.path);  // nicht in eine neue Baseline uebernehmen
        } catch (const std::exception& e) {
            logError("Quarantaene fehlgeschlagen fuer " + v.path + ": " + e.what());
        }
    }

    report::printFileReport(rep, cfg.quarantineThreshold);
    if (args.has("--json")) report::writeJson(report::toJson(rep), cfg.reportDir, "check");

    if (args.has("--update")) {
        fim::saveSnapshot(after, root, file);
        logInfo("Baseline aktualisiert");
    }
    return malicious > 0 ? kFindings : kOk;
}

int cmdQuarantine(const Config& cfg, const Args& args) {
    Quarantine q(cfg.quarantineDir, cfg.maxFileBytes);
    const std::string sub = args.positional.empty() ? "list" : args.positional[0];

    if (sub == "list") {
        const auto entries = q.list();
        std::cout << console::kBold << "Quarantäne: " << entries.size() << " Einträge" << console::kReset << "\n";
        if (entries.empty()) return kOk;
        for (const auto& e : entries) {
            std::cout << "\n  " << console::kMagenta << e.id << console::kReset << "  " << console::kGray << e.timestamp
                      << "  " << humanSize(e.originalSize) << console::kReset << "\n"
                      << "    " << e.originalPath << "\n"
                      << console::kGray << "    Grund: " << e.reason << "\n"
                      << "    SHA-256: " << e.sha256 << console::kReset << "\n";
        }
        std::cout << "\n" << console::kGray << "Wiederherstellen: wachturm quarantine restore <id>" << console::kReset << "\n";
        return kOk;
    }
    if (sub == "restore") {
        const std::string id = args.require(1, "Quarantaene-ID");
        std::optional<fs::path> target;
        if (auto to = args.opt("--to")) target = pathFromUtf8(*to);
        q.restore(id, target, args.has("--force"));
        std::cout << console::kGreen << "Wiederhergestellt.\n" << console::kReset;
        return kOk;
    }
    if (sub == "delete") {
        const std::string id = args.require(1, "Quarantaene-ID");
        if (!args.has("--force")) {
            std::cout << console::kYellow << "Eintrag " << id << " endgültig löschen? Das kann nicht rückgängig "
                      << "gemacht werden. [j/N] " << console::kReset << std::flush;
            std::string answer;
            std::getline(std::cin, answer);
            if (answer != "j" && answer != "J" && answer != "ja" && answer != "Ja") {
                std::cout << "Abgebrochen.\n";
                return kOk;
            }
        }
        q.purge(id);
        std::cout << console::kGreen << "Gelöscht.\n" << console::kReset;
        return kOk;
    }
    throw std::invalid_argument("Unbekannter Unterbefehl: quarantine " + sub);
}

}  // namespace

int main(int argc, char** argv) {
    console::init();
    try {
        const Args args = parseArgs(utf8Arguments(argc, argv));
        const fs::path configPath = args.opt("--config") ? pathFromUtf8(*args.opt("--config")) : fs::path("config.json");
        const Config cfg = loadConfig(configPath);

        Logger::instance().openFile(cfg.logFile);
        if (args.has("--verbose")) Logger::instance().setConsoleLevel(LogLevel::Debug);

        if (args.command.empty() || args.command == "help" || args.has("--help")) {
            if (cfg.showIntro && !args.has("--no-intro")) ui::showIntro(cfg, console::isTerminal());
            printHelp();
            return kOk;
        }

        logInfo("Start: " + args.command);
        if (args.command == "discover") return cmdDiscover(cfg, args);
        if (args.command == "scan") return cmdScan(cfg, args);
        if (args.command == "audit") return cmdAudit(cfg, args);
        if (args.command == "baseline") return cmdBaseline(cfg, args);
        if (args.command == "check") return cmdCheck(cfg, args);
        if (args.command == "quarantine") return cmdQuarantine(cfg, args);

        logError("Unbekannter Befehl: " + args.command);
        printHelp();
        return kError;
    } catch (const std::exception& e) {
        logError(e.what());
        return kError;
    }
}
