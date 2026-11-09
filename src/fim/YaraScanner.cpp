#include "fim/YaraScanner.hpp"

#include "core/Logger.hpp"
#include "core/Utf8.hpp"

#ifdef WT_HAVE_YARA
#include <yara.h>

#include <fstream>
#include <iterator>
#endif

namespace fs = std::filesystem;

namespace wt::fim {

#ifdef WT_HAVE_YARA

namespace {

struct CompileErrors {
    std::string file;
    int count = 0;
};

void compilerCallback(int errorLevel, const char* fileName, int line, const YR_RULE* /*rule*/,
                      const char* message, void* userData) {
    auto* errs = static_cast<CompileErrors*>(userData);
    const std::string where = (fileName ? std::string(fileName) : errs->file) + ":" + std::to_string(line);
    if (errorLevel == YARA_ERROR_LEVEL_ERROR) {
        ++errs->count;
        logError("YARA-Fehler " + where + ": " + message);
    } else {
        logWarn("YARA-Warnung " + where + ": " + message);
    }
}

int scanCallback(YR_SCAN_CONTEXT* /*ctx*/, int message, void* messageData, void* userData) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        const auto* rule = static_cast<const YR_RULE*>(messageData);
        static_cast<std::vector<std::string>*>(userData)->emplace_back(rule->identifier);
    }
    return CALLBACK_CONTINUE;
}

// Dateiinhalt als String lesen (std::ifstream kann unter Windows Unicode-Pfade).
bool readText(const fs::path& p, std::string& out) {
    std::ifstream in(p, std::ios::binary);
    if (!in) return false;
    out.assign(std::istreambuf_iterator<char>(in), {});
    return true;
}

}  // namespace

YaraScanner::YaraScanner() {
    initialized_ = (yr_initialize() == ERROR_SUCCESS);
    if (!initialized_) logError("YARA konnte nicht initialisiert werden");
}

YaraScanner::~YaraScanner() {
    if (rules_) yr_rules_destroy(static_cast<YR_RULES*>(rules_));
    if (initialized_) yr_finalize();
}

bool YaraScanner::loadRulesFromDir(const fs::path& dir) {
    if (!initialized_) return false;
    std::error_code ec;
    if (!fs::is_directory(dir, ec)) {
        logWarn("YARA-Regelordner fehlt: " + pathToUtf8(dir));
        return false;
    }

    YR_COMPILER* compiler = nullptr;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) return false;

    CompileErrors errs;
    yr_compiler_set_callback(compiler, compilerCallback, &errs);

    int fileCount = 0;
    for (const auto& entry : fs::directory_iterator(dir, ec)) {
        const auto ext = entry.path().extension();
        if (ext != ".yar" && ext != ".yara") continue;

        std::string source;
        errs.file = pathToUtf8(entry.path().filename());
        if (!readText(entry.path(), source)) {
            logWarn("Regeldatei nicht lesbar: " + errs.file);
            continue;
        }
        // Namespace = Dateiname, damit gleich benannte Regeln sich nicht stoeren
        yr_compiler_add_string(compiler, source.c_str(), errs.file.c_str());
        if (errs.count > 0) break;  // Nach einem Fehler ist der Compiler unbrauchbar (YARA-Doku)
        ++fileCount;
    }

    if (errs.count > 0 || fileCount == 0) {
        if (fileCount == 0 && errs.count == 0) logWarn("Keine YARA-Regeln in " + pathToUtf8(dir));
        yr_compiler_destroy(compiler);
        return false;
    }

    YR_RULES* rules = nullptr;
    const int rc = yr_compiler_get_rules(compiler, &rules);
    yr_compiler_destroy(compiler);
    if (rc != ERROR_SUCCESS) return false;

    if (rules_) yr_rules_destroy(static_cast<YR_RULES*>(rules_));
    rules_ = rules;
    logInfo("YARA: " + std::to_string(fileCount) + " Regeldatei(en) geladen");
    return true;
}

std::vector<std::string> YaraScanner::scan(std::span<const std::uint8_t> data) const {
    std::vector<std::string> matches;
    if (!rules_ || data.empty()) return matches;
    const int rc = yr_rules_scan_mem(static_cast<YR_RULES*>(rules_), data.data(), data.size(),
                                     SCAN_FLAGS_FAST_MODE, scanCallback, &matches, /*timeout s*/ 30);
    if (rc != ERROR_SUCCESS) logWarn("YARA-Scan fehlgeschlagen (Code " + std::to_string(rc) + ")");
    return matches;
}

#else  // ---------------- ohne YARA ----------------

YaraScanner::YaraScanner() = default;
YaraScanner::~YaraScanner() = default;

bool YaraScanner::loadRulesFromDir(const fs::path&) {
    logWarn("Wachturm wurde ohne YARA gebaut - YARA-Regeln werden ignoriert.");
    return false;
}

std::vector<std::string> YaraScanner::scan(std::span<const std::uint8_t>) const { return {}; }

#endif

}  // namespace wt::fim
