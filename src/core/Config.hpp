#pragma once
// Konfiguration (config.json). Jeder Wert hat einen sinnvollen Standard.

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace wt {

// Punkte, die eine verdaechtige Datei pro Merkmal bekommt (siehe Detector).
struct DetectionWeights {
    int blacklistHit = 100;
    int yaraMatch = 80;
    int doubleExtension = 50;        // z. B. "rechnung.pdf.exe"
    int highEntropyExecutable = 40;  // gepackt/verschluesselt UND ausfuehrbar
    int newOrModified = 20;          // neu oder geaendert seit der Baseline
};

struct Config {
    // --- Netzwerk ---
    int threads = 64;
    int connectTimeoutMs = 800;
    int bannerTimeoutMs = 1500;
    std::vector<std::uint16_t> discoveryPorts{80, 443, 22, 445, 139, 3389, 53, 8080, 5000, 62078};
    std::string defaultPorts =
        "1-1024,1433,1883,3306,3389,5000,5432,5900,6379,8000,8080,8443,9100,27017";

    // --- Pfade ---
    std::filesystem::path logFile = "wachturm.log";
    std::filesystem::path quarantineDir = "quarantine";
    std::filesystem::path logoPath = "logo.png";
    std::filesystem::path yaraRulesDir = "rules";
    std::filesystem::path blacklistFile = "blacklist.txt";
    std::filesystem::path baselineFile = "baseline.json";
    std::filesystem::path reportDir = "reports";

    // --- Datei-Ueberwachung / Erkennung ---
    double entropyThreshold = 7.2;  // 0..8 Bit pro Byte
    int quarantineThreshold = 80;   // ab dieser Punktzahl -> Quarantaene
    bool autoQuarantine = true;
    std::uint64_t maxFileBytes = 256ull * 1024 * 1024;
    std::vector<std::string> excludeDirs{".git", "node_modules"};
    DetectionWeights weights;

    // --- Oberflaeche ---
    bool showIntro = true;
    double introSeconds = 2.5;
};

// Laedt die Datei. Fehlt sie, wird eine Standarddatei geschrieben.
Config loadConfig(const std::filesystem::path& file);

void writeDefaultConfig(const std::filesystem::path& file, const Config& cfg);

// Unsinnige Werte korrigieren (z. B. threads = 0).
void validateConfig(Config& cfg);

}  // namespace wt
