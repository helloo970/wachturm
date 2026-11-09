#include "net/Targets.hpp"

#include <catch2/catch_test_macros.hpp>

#include <stdexcept>

using namespace wt::net;

TEST_CASE("IPv4 parsen", "[targets]") {
    REQUIRE(parseIpv4("192.168.178.1") == 0xC0A8B201u);
    REQUIRE(parseIpv4("0.0.0.0") == 0u);
    REQUIRE(parseIpv4("255.255.255.255") == 0xFFFFFFFFu);
    REQUIRE_FALSE(parseIpv4("256.1.1.1"));
    REQUIRE_FALSE(parseIpv4("1.2.3"));
    REQUIRE_FALSE(parseIpv4("1.2.3.4.5"));
    REQUIRE_FALSE(parseIpv4("1.2.3.x"));
    REQUIRE_FALSE(parseIpv4("1..3.4"));
    REQUIRE(ipv4ToString(0xC0A8B201u) == "192.168.178.1");
}

TEST_CASE("CIDR aufloesen", "[targets]") {
    const auto hosts = expandTargets("192.168.1.0/24");
    REQUIRE(hosts.size() == 254);  // ohne Netz- und Broadcast-Adresse
    REQUIRE(hosts.front() == *parseIpv4("192.168.1.1"));
    REQUIRE(hosts.back() == *parseIpv4("192.168.1.254"));

    REQUIRE(expandTargets("10.0.0.5/32").size() == 1);
    REQUIRE(expandTargets("10.0.0.4/31").size() == 2);
    // 10.0.0.77/30 -> Netz .76, nutzbar sind .77 und .78
    REQUIRE(expandTargets("10.0.0.77/30") == std::vector<std::uint32_t>{*parseIpv4("10.0.0.77"), *parseIpv4("10.0.0.78")});
}

TEST_CASE("Bereiche und Listen", "[targets]") {
    REQUIRE(expandTargets("192.168.1.10-20").size() == 11);
    REQUIRE(expandTargets("192.168.1.250-192.168.2.5").size() == 12);
    REQUIRE(expandTargets("10.0.0.1,10.0.0.1,10.0.0.2").size() == 2);  // Duplikate weg
    REQUIRE_THROWS_AS(expandTargets("192.168.1.20-10"), std::invalid_argument);
    REQUIRE_THROWS_AS(expandTargets("10.0.0.0/8", 1000), std::invalid_argument);
    REQUIRE_THROWS_AS(expandTargets("1.2.3.4/33"), std::invalid_argument);
}

TEST_CASE("Ports parsen", "[targets]") {
    const auto p = parsePortSpec("443, 22,80,20-23");
    REQUIRE(p == std::vector<std::uint16_t>{20, 21, 22, 23, 80, 443});
    REQUIRE(parsePortSpec("1-65535").size() == 65535);
    REQUIRE_THROWS_AS(parsePortSpec("0"), std::invalid_argument);
    REQUIRE_THROWS_AS(parsePortSpec("70000"), std::invalid_argument);
    REQUIRE_THROWS_AS(parsePortSpec("100-50"), std::invalid_argument);
    REQUIRE_THROWS_AS(parsePortSpec("abc"), std::invalid_argument);
}

TEST_CASE("Weitere Randfaelle", "[targets]") {
    REQUIRE(expandTargets("192.168.1.0/23").size() == 510);
    REQUIRE(expandTargets(" 10.0.0.1 , 10.0.0.2 ").size() == 2);
    REQUIRE(parsePortSpec(" 80 ") == std::vector<std::uint16_t>{80});
    REQUIRE(parsePortSpec("65535") == std::vector<std::uint16_t>{65535});
    REQUIRE(parsePortSpec("22,,23") == std::vector<std::uint16_t>{22, 23});
    REQUIRE_THROWS_AS(parsePortSpec(""), std::invalid_argument);
    REQUIRE_THROWS_AS(expandTargets(""), std::invalid_argument);
    REQUIRE_THROWS_AS(expandTargets("1.2.3.4-300"), std::invalid_argument);
}
