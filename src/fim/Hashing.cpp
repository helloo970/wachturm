#include "fim/Hashing.hpp"

#include "core/Utf8.hpp"

#include <openssl/evp.h>

#include <array>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <vector>

namespace wt::fim {
namespace {

using MdCtx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

MdCtx newSha256() {
    MdCtx ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (!ctx || EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
        throw std::runtime_error("OpenSSL: SHA-256 kann nicht initialisiert werden");
    }
    return ctx;
}

std::string finish(EVP_MD_CTX* ctx) {
    std::array<std::uint8_t, EVP_MAX_MD_SIZE> digest{};
    unsigned int len = 0;
    if (EVP_DigestFinal_ex(ctx, digest.data(), &len) != 1) {
        throw std::runtime_error("OpenSSL: SHA-256 fehlgeschlagen");
    }
    return toHex(std::span(digest.data(), len));
}

}  // namespace

std::string toHex(std::span<const std::uint8_t> data) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (std::uint8_t b : data) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0x0F]);
    }
    return out;
}

std::string sha256Hex(std::span<const std::uint8_t> data) {
    auto ctx = newSha256();
    if (EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1) {
        throw std::runtime_error("OpenSSL: SHA-256 Update fehlgeschlagen");
    }
    return finish(ctx.get());
}

std::string sha256File(const std::filesystem::path& file) {
    std::ifstream in(file, std::ios::binary);
    if (!in) throw std::runtime_error("Datei nicht lesbar: " + pathToUtf8(file));

    auto ctx = newSha256();
    std::vector<char> buffer(64 * 1024);
    while (in) {
        in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto got = in.gcount();
        if (got > 0 && EVP_DigestUpdate(ctx.get(), buffer.data(), static_cast<std::size_t>(got)) != 1) {
            throw std::runtime_error("OpenSSL: SHA-256 Update fehlgeschlagen");
        }
    }
    if (in.bad()) throw std::runtime_error("Lesefehler: " + pathToUtf8(file));
    return finish(ctx.get());
}

}  // namespace wt::fim
