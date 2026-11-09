#pragma once
// Duenne Huelle um libyara. Ohne YARA (WT_HAVE_YARA nicht gesetzt)
// ist available() == false und scan() liefert nichts.

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace wt::fim {

class YaraScanner {
public:
    YaraScanner();
    ~YaraScanner();
    YaraScanner(const YaraScanner&) = delete;
    YaraScanner& operator=(const YaraScanner&) = delete;

    // Kompiliert alle *.yar / *.yara im Ordner. false bei Fehlern.
    bool loadRulesFromDir(const std::filesystem::path& dir);

    bool available() const { return rules_ != nullptr; }

    // Namen aller passenden Regeln. Thread-sicher.
    std::vector<std::string> scan(std::span<const std::uint8_t> data) const;

private:
    void* rules_ = nullptr;  // YR_RULES*, als void* damit yara.h nicht im Header landet
    bool initialized_ = false;
};

}  // namespace wt::fim
