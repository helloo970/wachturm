#include "fim/Entropy.hpp"

#include <array>
#include <cmath>

namespace wt::fim {

double shannonEntropy(std::span<const std::uint8_t> data) {
    if (data.empty()) return 0.0;

    std::array<std::uint64_t, 256> counts{};
    for (std::uint8_t b : data) ++counts[b];

    // H = -Summe( p * log2(p) ) ueber alle vorkommenden Bytewerte
    const double total = static_cast<double>(data.size());
    double entropy = 0.0;
    for (std::uint64_t c : counts) {
        if (c == 0) continue;
        const double p = static_cast<double>(c) / total;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

}  // namespace wt::fim
