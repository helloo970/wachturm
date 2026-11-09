#include "fim/Baseline.hpp"
#include "fim/Detector.hpp"
#include "fim/Entropy.hpp"
#include "fim/Hashing.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_floating_point.hpp>

#include <numeric>
#include <string>
#include <vector>

using namespace wt::fim;
using Catch::Matchers::WithinAbs;

namespace {
std::vector<std::uint8_t> bytes(const std::string& s) { return {s.begin(), s.end()}; }
}

TEST_CASE("SHA-256 bekannter Wert", "[fim]") {
    REQUIRE(sha256Hex(bytes("abc")) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    REQUIRE(sha256Hex({}) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST_CASE("Entropie", "[fim]") {
    REQUIRE_THAT(shannonEntropy({}), WithinAbs(0.0, 1e-9));
    REQUIRE_THAT(shannonEntropy(bytes("aaaaaaaa")), WithinAbs(0.0, 1e-9));
    REQUIRE_THAT(shannonEntropy(bytes("abababab")), WithinAbs(1.0, 1e-9));

    std::vector<std::uint8_t> all(256);
    std::iota(all.begin(), all.end(), 0);
    REQUIRE_THAT(shannonEntropy(all), WithinAbs(8.0, 1e-9));  // jeder Bytewert genau einmal
}

TEST_CASE("Dateiendungen", "[fim]") {
    REQUIRE(isExecutableExtension("setup.EXE"));
    REQUIRE_FALSE(isExecutableExtension("foto.jpg"));
    REQUIRE(hasDoubleExtension("rechnung.pdf.exe"));
    REQUIRE_FALSE(hasDoubleExtension("setup.exe"));
    REQUIRE_FALSE(hasDoubleExtension("archiv.tar.gz"));
}

TEST_CASE("Snapshot-Vergleich", "[fim]") {
    Snapshot a{{"/a", {"111", 1, 0}}, {"/b", {"222", 1, 0}}, {"/c", {"333", 1, 0}}};
    Snapshot b{{"/b", {"222", 1, 0}}, {"/c", {"999", 1, 0}}, {"/d", {"444", 1, 0}}};
    const auto d = diffSnapshots(a, b);
    REQUIRE(d.removed == std::vector<std::string>{"/a"});
    REQUIRE(d.modified == std::vector<std::string>{"/c"});
    REQUIRE(d.added == std::vector<std::string>{"/d"});
    REQUIRE(diffSnapshots(a, a).empty());
}
