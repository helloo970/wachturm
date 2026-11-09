#include "core/Config.hpp"

#include "core/Logger.hpp"
#include "core/Utf8.hpp"

#include <algorithm>
#include <fstream>
#include <type_traits>
#include <nlohmann/json.hpp>
#include <stdexcept>

namespace fs = std::filesystem;
using nlohmann::json;

namespace wt {
namespace {

template <class T>
void readIf(const json& j, const char* key, T& out) {
    if (auto it = j.find(key); it != j.end() && !it->is_null()) {
        try {
            out = it->get<T>();
        } catch (const json::exception& e) {
            throw std::runtime_error(std::string("config.json: Schluessel '") + key +
                                     "' hat den falschen Typ (" + e.what() + ")");
        }
    }
}

void readPath(const json& j, const char* key, fs::path& out) {
    if (auto it = j.find(key); it != j.end() && it->is_string()) {
        out = pathFromUtf8(it->get<std::string>());
    }
}

}  // namespace

Config loadConfig(const fs::path& file) {
    Config cfg;

    std::error_code ec;
    if (!fs::exists(file, ec)) {
        logWarn("Keine " + pathToUtf8(file) + " gefunden - benutze Standardwerte.");
        writeDefaultConfig(file, cfg);
        return cfg;
    }

    std::ifstream in(file, std::ios::binary);
    if (!in) throw std::runtime_error("Konfiguration kann nicht gelesen werden: " + pathToUtf8(file));

    json j;
    try {
        j = json::parse(in, nullptr, /*allow_exceptions*/ true, /*ignore_comments*/ true);
    } catch (const json::parse_error& e) {
        throw std::runtime_error("config.json ist fehlerhaft: " + std::string(e.what()));
    }

    readIf(j, "threads", cfg.threads);
    readIf(j, "connect_timeout_ms", cfg.connectTimeoutMs);
    readIf(j, "banner_timeout_ms", cfg.bannerTimeoutMs);
    readIf(j, "discovery_ports", cfg.discoveryPorts);
    readIf(j, "default_ports", cfg.defaultPorts);

    readPath(j, "log_file", cfg.logFile);
    readPath(j, "quarantine_dir", cfg.quarantineDir);
    readPath(j, "logo_path", cfg.logoPath);
    readPath(j, "yara_rules_dir", cfg.yaraRulesDir);
    readPath(j, "blacklist_file", cfg.blacklistFile);
    readPath(j, "baseline_file", cfg.baselineFile);
    readPath(j, "report_dir", cfg.reportDir);

    readIf(j, "entropy_threshold", cfg.entropyThreshold);
    readIf(j, "quarantine_threshold", cfg.quarantineThreshold);
    readIf(j, "auto_quarantine", cfg.autoQuarantine);
    readIf(j, "max_file_bytes", cfg.maxFileBytes);
    readIf(j, "exclude_dirs", cfg.excludeDirs);

    if (auto it = j.find("weights"); it != j.end() && it->is_object()) {
        readIf(*it, "blacklist_hit", cfg.weights.blacklistHit);
        readIf(*it, "yara_match", cfg.weights.yaraMatch);
        readIf(*it, "double_extension", cfg.weights.doubleExtension);
        readIf(*it, "high_entropy_executable", cfg.weights.highEntropyExecutable);
        readIf(*it, "new_or_modified", cfg.weights.newOrModified);
    }

    readIf(j, "show_intro", cfg.showIntro);
    readIf(j, "intro_seconds", cfg.introSeconds);

    validateConfig(cfg);
    return cfg;
}

void writeDefaultConfig(const fs::path& file, const Config& cfg) {
    json j;
    j["threads"] = cfg.threads;
    j["connect_timeout_ms"] = cfg.connectTimeoutMs;
    j["banner_timeout_ms"] = cfg.bannerTimeoutMs;
    j["discovery_ports"] = cfg.discoveryPorts;
    j["default_ports"] = cfg.defaultPorts;

    j["log_file"] = pathToUtf8(cfg.logFile);
    j["quarantine_dir"] = pathToUtf8(cfg.quarantineDir);
    j["logo_path"] = pathToUtf8(cfg.logoPath);
    j["yara_rules_dir"] = pathToUtf8(cfg.yaraRulesDir);
    j["blacklist_file"] = pathToUtf8(cfg.blacklistFile);
    j["baseline_file"] = pathToUtf8(cfg.baselineFile);
    j["report_dir"] = pathToUtf8(cfg.reportDir);

    j["entropy_threshold"] = cfg.entropyThreshold;
    j["quarantine_threshold"] = cfg.quarantineThreshold;
    j["auto_quarantine"] = cfg.autoQuarantine;
    j["max_file_bytes"] = cfg.maxFileBytes;
    j["exclude_dirs"] = cfg.excludeDirs;

    j["weights"]["blacklist_hit"] = cfg.weights.blacklistHit;
    j["weights"]["yara_match"] = cfg.weights.yaraMatch;
    j["weights"]["double_extension"] = cfg.weights.doubleExtension;
    j["weights"]["high_entropy_executable"] = cfg.weights.highEntropyExecutable;
    j["weights"]["new_or_modified"] = cfg.weights.newOrModified;

    j["show_intro"] = cfg.showIntro;
    j["intro_seconds"] = cfg.introSeconds;

    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    if (!out) {
        logWarn("Standard-Konfiguration kann nicht geschrieben werden: " + pathToUtf8(file));
        return;
    }
    out << j.dump(2) << '\n';
    logInfo("Standard-Konfiguration geschrieben: " + pathToUtf8(file));
}

void validateConfig(Config& cfg) {
    // Wert auf [lo, hi] begrenzen und Korrektur melden
    auto limit = [](auto& value, auto lo, auto hi, const char* name) {
        const auto old = value;
        value = std::clamp(value, static_cast<std::decay_t<decltype(value)>>(lo),
                           static_cast<std::decay_t<decltype(value)>>(hi));
        if (value != old) {
            logWarn(std::string("config.json: '") + name + "' ausserhalb des erlaubten Bereichs - korrigiert");
        }
    };
    limit(cfg.threads, 1, 512, "threads");
    limit(cfg.connectTimeoutMs, 50, 10000, "connect_timeout_ms");
    limit(cfg.bannerTimeoutMs, 100, 10000, "banner_timeout_ms");
    limit(cfg.entropyThreshold, 0.0, 8.0, "entropy_threshold");
    limit(cfg.quarantineThreshold, 1, 100000, "quarantine_threshold");
    limit(cfg.introSeconds, 0.0, 10.0, "intro_seconds");
    limit(cfg.maxFileBytes, std::uint64_t{1024}, std::uint64_t{2048} * 1024 * 1024, "max_file_bytes");

    if (cfg.discoveryPorts.empty() ||
        std::find(cfg.discoveryPorts.begin(), cfg.discoveryPorts.end(), std::uint16_t{0}) != cfg.discoveryPorts.end()) {
        logWarn("config.json: 'discovery_ports' ungueltig - Standardliste wird benutzt");
        cfg.discoveryPorts = Config{}.discoveryPorts;
    }
}

}  // namespace wt
