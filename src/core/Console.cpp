#include "core/Console.hpp"

#include <cstdio>
#include <iostream>

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <sys/ioctl.h>
#include <unistd.h>
#endif

namespace wt::console {

void init() {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    for (DWORD which : {STD_OUTPUT_HANDLE, STD_ERROR_HANDLE}) {
        HANDLE h = GetStdHandle(which);
        if (h == INVALID_HANDLE_VALUE || h == nullptr) continue;
        DWORD mode = 0;
        if (GetConsoleMode(h, &mode)) {
            SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }
#endif
    std::ios::sync_with_stdio(true);
}

bool isTerminal() {
#ifdef _WIN32
    return _isatty(_fileno(stdout)) != 0;
#else
    return ::isatty(STDOUT_FILENO) != 0;
#endif
}

int terminalWidth() {
#ifdef _WIN32
    CONSOLE_SCREEN_BUFFER_INFO info{};
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &info)) {
        return info.srWindow.Right - info.srWindow.Left + 1;
    }
#else
    winsize ws{};
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) return ws.ws_col;
#endif
    return 80;
}

void hideCursor()  { std::fputs("\x1b[?25l", stdout); std::fflush(stdout); }
void showCursor()  { std::fputs("\x1b[?25h", stdout); std::fflush(stdout); }
void cursorHome()  { std::fputs("\x1b[H", stdout); }
void clearScreen() { std::fputs("\x1b[2J\x1b[H", stdout); std::fflush(stdout); }

std::string fg(int r, int g, int b) {
    return "\x1b[38;2;" + std::to_string(r) + ';' + std::to_string(g) + ';' + std::to_string(b) + 'm';
}

std::size_t visibleWidth(std::string_view s) {
    std::size_t width = 0;
    for (std::size_t i = 0; i < s.size(); ++i) {
        const auto c = static_cast<unsigned char>(s[i]);
        if (c == 0x1b) {
            // ANSI-Sequenz "ESC [ ... Buchstabe" ueberspringen
            ++i;
            if (i < s.size() && s[i] == '[') {
                while (i + 1 < s.size() && !((s[i + 1] >= 'A' && s[i + 1] <= 'Z') ||
                                             (s[i + 1] >= 'a' && s[i + 1] <= 'z'))) {
                    ++i;
                }
                ++i;
            }
            continue;
        }
        // UTF-8-Folgebytes (10xxxxxx) zaehlen nicht als eigene Spalte
        if ((c & 0xC0) != 0x80) ++width;
    }
    return width;
}

}  // namespace wt::console
