#pragma once
// Bewertet einzelne Dateien und vergibt Punkte (Score).
// Ab cfg.quarantineThreshold Punkten gilt eine Datei als schaedlich.

#include "core/Config.hpp"
#include "fim/YaraScanner.hpp"

#include <filesystem>
#include <string>
#include <unordered_set>
#include <vector>

namespace wt::fim {

struct Verdict {
    std::string path;
    std::string sha256;
    int score = 0;
    double entropy = 0.0;
    std::vector<std::string> reasons;
    bool protectedPath = false;  // Systemordner -> niemals automatisch verschieben
    bool quarantined = false;
    std::string quarantineId;
};

class Detector {
public:
    explicit Detector(const Config& cfg);

    // isNewOrModified: laut Baseline-Vergleich neu oder geaendert
    Verdict evaluate(const std::filesystem::path& file, const std::string& sha256, bool isNewOrModified) const;

    bool isMalicious(const Verdict& v) const { return v.score >= cfg_.quarantineThreshold; }
    bool yaraAvailable() const { return yara_.available(); }
    std::size_t blacklistSize() const { return blacklist_.size(); }

private:
    void loadBlacklist(const std::filesystem::path& file);

    const Config& cfg_;
    std::unordered_set<std::string> blacklist_;  // SHA-256, kleingeschrieben
    YaraScanner yara_;
};

bool isExecutableExtension(const std::filesystem::path& p);
bool hasDoubleExtension(const std::filesystem::path& p);   // "foto.jpg.exe"
bool isProtectedSystemPath(const std::filesystem::path& p);

}  // namespace wt::fim
