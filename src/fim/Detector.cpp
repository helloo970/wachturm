#include "fim/Detector.hpp"

#include "core/Logger.hpp"
#include "core/Utf8.hpp"
#include "fim/Entropy.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <string_view>

namespace fs = std::filesystem;

namespace wt::fim {
namespace {

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string lowerExt(const fs::path& p) { return lower(pathToUtf8(p.extension())); }

// Liest hoechstens maxBytes vom Dateianfang.
std::vector<std::uint8_t> readHead(const fs::path& file, std::uint64_t maxBytes) {
    std::ifstream in(file, std::ios::binary);
    if (!in) return {};
    std::error_code ec;
    const auto size = fs::file_size(file, ec);
    const auto toRead = static_cast<std::size_t>(std::min<std::uint64_t>(ec ? maxBytes : size, maxBytes));
    std::vector<std::uint8_t> buf(toRead);
    in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(toRead));
    buf.resize(static_cast<std::size_t>(in.gcount()));
    return buf;
}

// Ausfuehrbares Format am Dateianfang erkennen - egal welche Endung.
bool hasExecutableMagic(std::span<const std::uint8_t> d) {
    if (d.size() >= 2 && d[0] == 'M' && d[1] == 'Z') return true;                          // Windows PE
    if (d.size() >= 4 && d[0] == 0x7F && d[1] == 'E' && d[2] == 'L' && d[3] == 'F') return true;  // Linux ELF
    return false;
}

std::string fmt1(double v) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%.2f", v);
    return buf;
}

}  // namespace

bool isExecutableExtension(const fs::path& p) {
    static constexpr std::array<std::string_view, 30> kExec{
        // Windows-Programme und -Bibliotheken
        ".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".sys", ".ocx", ".msi", ".msp",
        // Skripte
        ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta",
        // Verknuepfungen / Office-Makros / Java
        ".lnk", ".jar", ".docm", ".xlsm", ".pptm",
        // Linux / macOS
        ".sh", ".elf", ".so", ".app"};
    const std::string ext = lowerExt(p);
    return std::find(kExec.begin(), kExec.end(), ext) != kExec.end();
}

bool hasDoubleExtension(const fs::path& p) {
    // "rechnung.pdf.exe" -> letzte Endung ausfuehrbar, vorletzte sieht harmlos aus
    if (!isExecutableExtension(p)) return false;
    static constexpr std::array<std::string_view, 12> kDecoy{
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt", ".mp3", ".mp4", ".zip"};
    const std::string inner = lowerExt(p.stem());
    return std::find(kDecoy.begin(), kDecoy.end(), inner) != kDecoy.end();
}

bool isProtectedSystemPath(const fs::path& p) {
    const std::string s = lower(pathToUtf8(p));
#ifdef _WIN32
    static constexpr std::array<std::string_view, 4> kProtected{
        "c:\\windows\\", "c:\\program files\\", "c:\\program files (x86)\\", "c:\\programdata\\microsoft\\"};
#else
    static constexpr std::array<std::string_view, 7> kProtected{
        "/bin/", "/sbin/", "/usr/", "/lib/", "/lib64/", "/boot/", "/etc/"};
#endif
    return std::any_of(kProtected.begin(), kProtected.end(),
                       [&](std::string_view pre) { return s.rfind(pre, 0) == 0; });
}

Detector::Detector(const Config& cfg) : cfg_(cfg) {
    loadBlacklist(cfg.blacklistFile);
    yara_.loadRulesFromDir(cfg.yaraRulesDir);
    logInfo("Detector bereit: " + std::to_string(blacklist_.size()) + " Blacklist-Hashes, YARA " +
            (yara_.available() ? "aktiv" : "inaktiv"));
}

void Detector::loadBlacklist(const fs::path& file) {
    std::ifstream in(file, std::ios::binary);
    if (!in) {
        logWarn("Keine Blacklist gefunden: " + pathToUtf8(file));
        return;
    }

    std::string line;
    std::size_t lineNo = 0, invalid = 0;
    while (std::getline(in, line)) {
        ++lineNo;
        // Leerraum und Windows-'\r' an beiden Enden entfernen
        const auto first = line.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) continue;
        const auto last = line.find_last_not_of(" \t\r\n");
        line = line.substr(first, last - first + 1);
        if (line[0] == '#') continue;

        // Erlaubt auch Formate wie "<hash>  dateiname" (sha256sum-Ausgabe)
        if (const auto space = line.find_first_of(" \t"); space != std::string::npos) line.resize(space);

        const bool valid = line.size() == 64 && std::all_of(line.begin(), line.end(), [](unsigned char c) {
                               return std::isxdigit(c) != 0;
                           });
        if (!valid) {
            ++invalid;
            logDebug("Blacklist Zeile " + std::to_string(lineNo) + " ist kein SHA-256 - ignoriert");
            continue;
        }
        blacklist_.insert(lower(line));
    }
    if (invalid > 0) logWarn("Blacklist: " + std::to_string(invalid) + " ungueltige Zeile(n) ignoriert");
}

Verdict Detector::evaluate(const fs::path& file, const std::string& sha256, bool isNewOrModified) const {
    Verdict v;
    v.path = pathToUtf8(file);
    v.sha256 = sha256;
    v.protectedPath = isProtectedSystemPath(file);
    const auto& w = cfg_.weights;

    // 1) Bekannte Schadsoftware (exakter Hash)
    if (blacklist_.count(lower(sha256)) > 0) {
        v.score += w.blacklistHit;
        v.reasons.push_back("Hash steht auf der Blacklist");
    }

    // 2) Inhalt lesen: Entropie + YARA + Magic Bytes
    const auto data = readHead(file, cfg_.maxFileBytes);
    v.entropy = shannonEntropy(data);

    for (const auto& rule : yara_.scan(data)) {
        v.score += w.yaraMatch;
        v.reasons.push_back("YARA-Regel: " + rule);
    }

    const bool executable = isExecutableExtension(file) || hasExecutableMagic(data);
    if (executable && v.entropy >= cfg_.entropyThreshold) {
        v.score += w.highEntropyExecutable;
        v.reasons.push_back("Ausfuehrbar und hohe Entropie (" + fmt1(v.entropy) + ") - evtl. gepackt");
    }

    // 3) Tarnung: "bild.jpg.exe" oder ausfuehrbarer Inhalt mit harmloser Endung
    if (hasDoubleExtension(file)) {
        v.score += w.doubleExtension;
        v.reasons.push_back("Doppelte Dateiendung");
    } else if (hasExecutableMagic(data) && !isExecutableExtension(file) && !file.extension().empty()) {
        const std::string ext = lowerExt(file);
        static constexpr std::array<std::string_view, 6> kHarmless{".pdf", ".jpg", ".png", ".txt", ".doc", ".docx"};
        if (std::find(kHarmless.begin(), kHarmless.end(), ext) != kHarmless.end()) {
            v.score += w.doubleExtension;
            v.reasons.push_back("Programmcode getarnt als " + ext);
        }
    }

    // 4) Neu/geaendert seit der Baseline (allein nie genug fuer Quarantaene)
    if (isNewOrModified) {
        v.score += w.newOrModified;
        v.reasons.push_back("Neu oder geaendert seit Baseline");
    }
    return v;
}

}  // namespace wt::fim
