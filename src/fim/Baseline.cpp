#include "fim/Baseline.hpp"

#include "core/Logger.hpp"
#include "core/Utf8.hpp"
#include "fim/Hashing.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <fstream>
#include <future>
#include <nlohmann/json.hpp>
#include <optional>
#include <stdexcept>

namespace fs = std::filesystem;
using nlohmann::json;

namespace wt::fim {
namespace {

constexpr int kFormatVersion = 1;

// Normalisierter absoluter Pfad (existiert er nicht, trotzdem sinnvoll).
fs::path normalized(const fs::path& p) {
    std::error_code ec;
    auto r = fs::weakly_canonical(fs::absolute(p, ec), ec);
    return ec ? fs::absolute(p) : r;
}

bool isInside(const fs::path& child, const fs::path& parent) {
    auto c = child.begin();
    for (auto it = parent.begin(); it != parent.end(); ++it, ++c) {
        if (it->empty()) continue;  // abschliessender Slash
        if (c == child.end() || *c != *it) return false;
    }
    return true;
}

std::vector<fs::path> collectFiles(const fs::path& root, const Config& cfg) {
    const fs::path quarantine = normalized(cfg.quarantineDir);
    const fs::path baselineFile = normalized(cfg.baselineFile);
    const fs::path logFile = normalized(cfg.logFile);

    std::vector<fs::path> files;
    std::error_code ec;
    fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec);
    if (ec) throw std::runtime_error("Ordner nicht lesbar: " + pathToUtf8(root) + " (" + ec.message() + ")");

    const auto end = fs::end(it);
    for (; it != end; it.increment(ec)) {
        if (ec) {
            logWarn("Uebersprungen: " + ec.message());
            ec.clear();
            continue;
        }
        const fs::directory_entry& entry = *it;
        std::error_code e2;

        if (entry.is_symlink(e2)) {
            // Symlinks nicht folgen (Endlosschleifen, Dateien ausserhalb von root)
            if (entry.is_directory(e2)) it.disable_recursion_pending();
            continue;
        }
        if (entry.is_directory(e2)) {
            const std::string name = pathToUtf8(entry.path().filename());
            const bool excluded = std::find(cfg.excludeDirs.begin(), cfg.excludeDirs.end(), name) != cfg.excludeDirs.end();
            if (excluded || isInside(normalized(entry.path()), quarantine)) it.disable_recursion_pending();
            continue;
        }
        if (!entry.is_regular_file(e2)) continue;

        const fs::path abs = normalized(entry.path());
        if (abs == baselineFile || abs == logFile) continue;  // eigene Dateien ignorieren
        files.push_back(abs);
    }
    return files;
}

std::optional<FileRecord> hashOne(const fs::path& file) {
    try {
        FileRecord r;
        r.size = fs::file_size(file);
        const auto t = fs::last_write_time(file);
        r.mtime = std::chrono::duration_cast<std::chrono::seconds>(t.time_since_epoch()).count();
        r.sha256 = sha256File(file);
        return r;
    } catch (const std::exception& e) {
        // Gesperrte Dateien (z. B. pagefile.sys) sind normal -> nur loggen
        logDebug("Nicht gehasht: " + pathToUtf8(file) + " - " + e.what());
        return std::nullopt;
    }
}

}  // namespace

Snapshot buildSnapshot(const fs::path& root, const Config& cfg, ThreadPool& pool, const ProgressFn& progress) {
    const fs::path absRoot = normalized(root);
    std::error_code ec;
    if (!fs::is_directory(absRoot, ec)) throw std::runtime_error("Kein Ordner: " + pathToUtf8(absRoot));

    logInfo("Sammle Dateien in " + pathToUtf8(absRoot) + " ...");
    const std::vector<fs::path> files = collectFiles(absRoot, cfg);
    logInfo(std::to_string(files.size()) + " Dateien werden gehasht");

    std::atomic<std::size_t> done{0};
    std::vector<std::future<std::optional<FileRecord>>> futures;
    futures.reserve(files.size());
    for (const auto& f : files) {
        futures.push_back(pool.submit([&f, &done, &progress, total = files.size()] {
            auto r = hashOne(f);
            const auto n = ++done;
            if (progress) progress(n, total);
            return r;
        }));
    }

    Snapshot snap;
    for (std::size_t i = 0; i < files.size(); ++i) {
        if (auto rec = futures[i].get()) snap.emplace(pathToUtf8(files[i]), std::move(*rec));
    }
    return snap;
}

void saveSnapshot(const Snapshot& snap, const fs::path& root, const fs::path& file) {
    json j;
    j["version"] = kFormatVersion;
    j["root"] = pathToUtf8(normalized(root));
    j["created"] = currentTimestamp();
    json& files = j["files"] = json::object();
    for (const auto& [path, rec] : snap) {
        files[path] = {{"sha256", rec.sha256}, {"size", rec.size}, {"mtime", rec.mtime}};
    }

    // Erst in temporaere Datei schreiben, dann umbenennen -> nie halb geschriebene Baseline
    fs::path tmp = file;
    tmp += ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) throw std::runtime_error("Baseline kann nicht geschrieben werden: " + pathToUtf8(file));
        out << j.dump(1);
        if (!out) throw std::runtime_error("Schreibfehler: " + pathToUtf8(tmp));
    }
    fs::rename(tmp, file);
}

Snapshot loadSnapshot(const fs::path& file, fs::path* rootOut) {
    std::ifstream in(file, std::ios::binary);
    if (!in) throw std::runtime_error("Keine Baseline gefunden: " + pathToUtf8(file) +
                                      " - zuerst 'wachturm baseline <ordner>' ausfuehren.");
    json j;
    try {
        j = json::parse(in);
    } catch (const json::parse_error& e) {
        throw std::runtime_error("Baseline ist beschaedigt: " + std::string(e.what()));
    }
    if (j.value("version", 0) != kFormatVersion) throw std::runtime_error("Unbekannte Baseline-Version");
    if (rootOut) *rootOut = pathFromUtf8(j.at("root").get<std::string>());

    Snapshot snap;
    for (const auto& [path, rec] : j.at("files").items()) {
        snap.emplace(path, FileRecord{rec.at("sha256").get<std::string>(), rec.at("size").get<std::uint64_t>(),
                                      rec.at("mtime").get<std::int64_t>()});
    }
    return snap;
}

SnapshotDiff diffSnapshots(const Snapshot& before, const Snapshot& after) {
    // Beide Maps sind sortiert -> ein gemeinsamer Durchlauf (Merge) reicht: O(n + m)
    SnapshotDiff diff;
    auto a = before.begin();
    auto b = after.begin();
    while (a != before.end() || b != after.end()) {
        if (b == after.end() || (a != before.end() && a->first < b->first)) {
            diff.removed.push_back(a->first);
            ++a;
        } else if (a == before.end() || b->first < a->first) {
            diff.added.push_back(b->first);
            ++b;
        } else {
            if (a->second.sha256 != b->second.sha256) diff.modified.push_back(b->first);
            ++a;
            ++b;
        }
    }
    return diff;
}

}  // namespace wt::fim
