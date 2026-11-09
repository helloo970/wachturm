#include "quarantine/Quarantine.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <random>
#include <string>

namespace fs = std::filesystem;

namespace {

struct TempDir {
    fs::path path;
    TempDir() {
        std::random_device rd;
        path = fs::temp_directory_path() / ("wachturm_test_" + std::to_string(rd()));
        fs::create_directories(path);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

void writeFile(const fs::path& p, const std::string& content) {
    std::ofstream out(p, std::ios::binary);
    out << content;
}

std::string readFile(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), {}};
}

}  // namespace

TEST_CASE("Quarantaene: verschieben und wiederherstellen", "[quarantine]") {
    TempDir tmp;
    const fs::path victim = tmp.path / fs::path(u8"böse.exe");  // Umlaut absichtlich
    const std::string content(100000, 'A');
    writeFile(victim, content + "Ende");

    wt::Quarantine q(tmp.path / "q", 1024 * 1024);
    const auto entry = q.isolate(victim, "Test");

    REQUIRE_FALSE(fs::exists(victim));
    REQUIRE(fs::exists(tmp.path / "q" / (entry.id + ".wtq")));
    // Komprimiert: 100 KB 'A' muessen deutlich kleiner werden
    REQUIRE(fs::file_size(tmp.path / "q" / (entry.id + ".wtq")) < 2000);
    REQUIRE(q.list().size() == 1);

    // Neues Objekt -> Index und Schluessel werden von der Platte geladen
    wt::Quarantine q2(tmp.path / "q", 1024 * 1024);
    REQUIRE(q2.list().size() == 1);
    q2.restore(entry.id);

    REQUIRE(fs::exists(victim));
    REQUIRE(readFile(victim) == content + "Ende");
    REQUIRE(q2.list().empty());
}

TEST_CASE("Quarantaene: Manipulation wird erkannt", "[quarantine]") {
    TempDir tmp;
    const fs::path victim = tmp.path / "x.bin";
    writeFile(victim, "geheimer Inhalt");

    wt::Quarantine q(tmp.path / "q", 1024 * 1024);
    const auto entry = q.isolate(victim, "Test");
    const fs::path blob = tmp.path / "q" / (entry.id + ".wtq");

    // Ein Byte im verschluesselten Teil kippen
    {
        std::fstream f(blob, std::ios::binary | std::ios::in | std::ios::out);
        f.seekp(40);
        char c = 0;
        f.seekg(40);
        f.get(c);
        f.seekp(40);
        f.put(static_cast<char>(c ^ 0x01));
    }
    REQUIRE_THROWS(q.restore(entry.id));
    REQUIRE_FALSE(fs::exists(victim));  // nichts Kaputtes wiederhergestellt
}

TEST_CASE("Quarantaene: zu grosse Datei bleibt liegen", "[quarantine]") {
    TempDir tmp;
    const fs::path victim = tmp.path / "gross.bin";
    writeFile(victim, std::string(5000, 'x'));
    wt::Quarantine q(tmp.path / "q", 1000);
    REQUIRE_THROWS(q.isolate(victim, "Test"));
    REQUIRE(fs::exists(victim));
}
