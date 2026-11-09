#pragma once
// SHA-256 ueber OpenSSL (EVP-API).

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>

namespace wt::fim {

// Liest die Datei in Bloecken - funktioniert auch fuer riesige Dateien.
// Wirft std::runtime_error, wenn die Datei nicht gelesen werden kann.
std::string sha256File(const std::filesystem::path& file);

std::string sha256Hex(std::span<const std::uint8_t> data);

std::string toHex(std::span<const std::uint8_t> data);

}  // namespace wt::fim
