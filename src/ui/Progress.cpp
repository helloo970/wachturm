#include "ui/Progress.hpp"

#include "core/Console.hpp"

#include <cstdio>
#include <string>

namespace wt::ui {

void ProgressBar::update(std::size_t done, std::size_t total) {
    if (!enabled_) return;
    std::lock_guard lock(mutex_);
    if (finished_) return;
    lastTotal_ = total;
    const auto now = std::chrono::steady_clock::now();
    // Drosseln: Konsolenausgabe ist langsam, 65535 Ports = 65535 Aufrufe
    if (done < total && now - lastDraw_ < std::chrono::milliseconds(50)) return;
    lastDraw_ = now;
    draw(done, total);
}

void ProgressBar::finish() {
    if (!enabled_) return;
    std::lock_guard lock(mutex_);
    if (finished_) return;
    finished_ = true;
    draw(lastTotal_, lastTotal_);
    std::fputs("\n", stdout);
    std::fflush(stdout);
}

void ProgressBar::draw(std::size_t done, std::size_t total) {
    constexpr std::size_t kWidth = 30;
    if (done > total) done = total;
    const std::size_t percent = total == 0 ? 100 : done * 100 / total;
    const std::size_t filled = total == 0 ? kWidth : done * kWidth / total;

    std::string bar;
    for (std::size_t i = 0; i < kWidth; ++i) bar += (i < filled) ? "█" : "░";

    // "\r" springt an den Zeilenanfang, "\x1b[K" loescht den Rest der Zeile
    std::string line = "\r";
    line += console::kCyan;
    line += label_;
    line += console::kReset;
    line += "  ";
    line += (percent == 100) ? console::kGreen : console::kBlue;
    line += bar;
    line += console::kReset;
    line += "  " + std::to_string(percent) + "%  (" + std::to_string(done) + "/" + std::to_string(total) + ")\x1b[K";
    std::fputs(line.c_str(), stdout);
    std::fflush(stdout);
}

}  // namespace wt::ui
