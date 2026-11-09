#include "core/ThreadPool.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <stdexcept>

TEST_CASE("ThreadPool fuehrt alles aus", "[pool]") {
    std::atomic<int> sum{0};
    {
        wt::ThreadPool pool(8);
        for (int i = 1; i <= 1000; ++i) pool.submit([&sum, i] { sum += i; });
    }  // Destruktor arbeitet die Warteschlange ab
    REQUIRE(sum == 500500);
}

TEST_CASE("ThreadPool liefert Ergebnisse und Exceptions", "[pool]") {
    wt::ThreadPool pool(2);
    auto ok = pool.submit([] { return 42; });
    auto bad = pool.submit([]() -> int { throw std::runtime_error("kaputt"); });
    REQUIRE(ok.get() == 42);
    REQUIRE_THROWS_AS(bad.get(), std::runtime_error);
}

TEST_CASE("ThreadPool mit 0 Threads benutzt trotzdem einen", "[pool]") {
    wt::ThreadPool pool(0);
    REQUIRE(pool.size() == 1);
    REQUIRE(pool.submit([] { return 7; }).get() == 7);
}
