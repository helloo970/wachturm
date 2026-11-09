#pragma once
// Konsolen-Hilfen: ANSI-Farben, Cursor, UTF-8 unter Windows.

#include <string>
#include <string_view>

namespace wt::console {

// Muss ganz am Anfang von main() aufgerufen werden.
// Aktiviert unter Windows ANSI-Escape-Sequenzen und UTF-8-Ausgabe.
void init();

bool isTerminal();     // false, wenn die Ausgabe umgeleitet wird (> datei.txt)
int terminalWidth();   // Spalten, Fallback 80

void hideCursor();
void showCursor();
void cursorHome();
void clearScreen();

std::string fg(int r, int g, int b);  // 24-Bit-Vordergrundfarbe

inline constexpr std::string_view kReset  = "\x1b[0m";
inline constexpr std::string_view kBold   = "\x1b[1m";
inline constexpr std::string_view kDim    = "\x1b[2m";
inline constexpr std::string_view kRed    = "\x1b[31m";
inline constexpr std::string_view kGreen  = "\x1b[32m";
inline constexpr std::string_view kYellow = "\x1b[33m";
inline constexpr std::string_view kBlue   = "\x1b[34m";
inline constexpr std::string_view kMagenta= "\x1b[35m";
inline constexpr std::string_view kCyan   = "\x1b[36m";
inline constexpr std::string_view kGray   = "\x1b[90m";

// Sichtbare Breite eines UTF-8-Strings (ohne ANSI-Codes, 1 Spalte pro Codepoint).
std::size_t visibleWidth(std::string_view s);

}  // namespace wt::console
