#pragma once
// Shannon-Entropie in Bit pro Byte (0.0 .. 8.0).
//   Text ~ 4-5, normale .exe ~ 5-6.5, gepackt/verschluesselt/komprimiert > 7.2

#include <cstdint>
#include <span>

namespace wt::fim {

double shannonEntropy(std::span<const std::uint8_t> data);

}  // namespace wt::fim
