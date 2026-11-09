#pragma once
// Hilfsfunktionen fuer UTF-8 <-> std::filesystem::path.
// Unter Windows wuerde path(std::string) die ANSI-Codepage benutzen und
// Umlaute in Pfaden kaputt machen. Darum gehen alle Pfade, die in JSON
// oder Logs landen, durch diese beiden Funktionen.

#include <filesystem>
#include <string>
#include <string_view>

namespace wt {

inline std::filesystem::path pathFromUtf8(std::string_view s) {
    return std::filesystem::path(std::u8string(s.begin(), s.end()));
}

inline std::string pathToUtf8(const std::filesystem::path& p) {
    const std::u8string u = p.u8string();
    return std::string(u.begin(), u.end());
}

}  // namespace wt
