#pragma once
// Fortschrittsanzeige, die von vielen Threads gleichzeitig aufgerufen werden darf.

#include "core/ThreadPool.hpp"

#include <chrono>
#include <cstddef>
#include <memory>
#include <mutex>
#include <string>

namespace wt::ui {

class ProgressBar {
public:
    ProgressBar(std::string label, bool enabled) : label_(std::move(label)), enabled_(enabled) {}

    // Thread-sicher. Zeichnet hoechstens ~20x pro Sekunde neu.
    void update(std::size_t done, std::size_t total);
    // Abschliessen (100 % zeichnen + Zeilenumbruch)
    void finish();

    // Als ProgressFn fuer HostDiscovery/PortScanner/buildSnapshot benutzen
    static ProgressFn callback(const std::shared_ptr<ProgressBar>& bar) {
        return [bar](std::size_t d, std::size_t t) { bar->update(d, t); };
    }

private:
    void draw(std::size_t done, std::size_t total);

    std::string label_;
    bool enabled_;
    std::mutex mutex_;
    std::chrono::steady_clock::time_point lastDraw_{};
    std::size_t lastTotal_ = 0;
    bool finished_ = false;
};

}  // namespace wt::ui
