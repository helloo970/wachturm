#pragma once
// File-Integrity-Monitoring: "Fingerabdruck" eines Ordners speichern und
// spaeter vergleichen (neu / geaendert / geloescht).

#include "core/Config.hpp"
#include "core/ThreadPool.hpp"

#include <cstdint>
#include <filesystem>
#include <map>
#include <string>
#include <vector>

namespace wt::fim {

struct FileRecord {
    std::string sha256;
    std::uint64_t size = 0;
    std::int64_t mtime = 0;  // Sekunden (nur lokal vergleichbar)
};

// Schluessel: absoluter Pfad als UTF-8
using Snapshot = std::map<std::string, FileRecord>;

struct SnapshotDiff {
    std::vector<std::string> added;
    std::vector<std::string> modified;
    std::vector<std::string> removed;
    bool empty() const { return added.empty() && modified.empty() && removed.empty(); }
};

// Hasht alle Dateien unter root parallel.
// Ausgelassen werden: exclude_dirs, der Quarantaene-Ordner, Symlinks.
Snapshot buildSnapshot(const std::filesystem::path& root, const Config& cfg, ThreadPool& pool,
                       const ProgressFn& progress = {});

void saveSnapshot(const Snapshot& snap, const std::filesystem::path& root, const std::filesystem::path& file);

// rootOut bekommt den Ordner, fuer den die Baseline erstellt wurde.
Snapshot loadSnapshot(const std::filesystem::path& file, std::filesystem::path* rootOut = nullptr);

SnapshotDiff diffSnapshots(const Snapshot& before, const Snapshot& after);

}  // namespace wt::fim
