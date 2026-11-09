#include "ui/Banner.hpp"

#include "core/Console.hpp"
#include "core/Logger.hpp"
#include "core/Utf8.hpp"

#include <stb_image.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <numbers>
#include <string>
#include <string_view>
#include <thread>

namespace fs = std::filesystem;

namespace wt::ui {
namespace {

// ---------------------------------------------------------------------------
// Inhalt des Befehls-Kastens
// ---------------------------------------------------------------------------
struct CommandHint {
    std::string_view command;
    std::string_view description;
};

// Slogan unter dem Namen
constexpr std::string_view kTagline = "Wacht über dein Heimnetz";

// Maximal ~34 Zeichen pro Zeile, sonst wird der Kasten breiter.
constexpr CommandHint kTopCommands[5] = {
    {"discover <netz>", "Geräte im Heimnetz finden"},
    {"audit <netz>", "Ports + unsichere Dienste prüfen"},
    {"baseline <ordner>", "Datei-Fingerabdruck speichern"},
    {"check <ordner>", "Änderungen & Malware suchen"},
    {"quarantine list", "Quarantäne anzeigen"},
};

std::vector<std::string> panelLines() {
    using namespace console;
    std::vector<std::string> lines;
    lines.push_back(std::string(kBold) + std::string(kCyan) + "WACHTURM" + std::string(kReset) +
                    std::string(kGray) + "  v" WT_VERSION + std::string(kReset));
    lines.push_back(std::string(kGray) + std::string(kTagline) + std::string(kReset));
    lines.emplace_back();
    lines.push_back(std::string(kBold) + "Wichtigste Befehle:" + std::string(kReset));
    for (const auto& c : kTopCommands) {
        lines.push_back("  " + std::string(kGreen) + std::string(c.command) + std::string(kReset));
        lines.push_back("    " + std::string(kGray) + std::string(c.description) + std::string(kReset));
    }
    return lines;
}

// ---------------------------------------------------------------------------
// Bild-Hilfen
// ---------------------------------------------------------------------------
const std::uint8_t* pixelAt(const RgbaImage& img, int x, int y) {
    x = std::clamp(x, 0, img.width - 1);
    y = std::clamp(y, 0, img.height - 1);
    return &img.pixels[(static_cast<std::size_t>(y) * img.width + x) * 4];
}

double luminance(const std::uint8_t* p) {
    return (0.2126 * p[0] + 0.7152 * p[1] + 0.0722 * p[2]) / 255.0;
}

// ---------------------------------------------------------------------------
// Kasten zusammensetzen
// ---------------------------------------------------------------------------
std::string repeat(std::string_view s, int n) {
    std::string out;
    for (int i = 0; i < n; ++i) out += s;
    return out;
}

void appendLogoRow(std::string& out, const std::vector<Cell>& row) {
    int lr = -1, lg = -1, lb = -1;
    for (const Cell& c : row) {
        if (c.ch != ' ' && (c.r != lr || c.g != lg || c.b != lb)) {
            out += console::fg(c.r, c.g, c.b);
            lr = c.r; lg = c.g; lb = c.b;
        }
        out.push_back(c.ch);
    }
    out += console::kReset;
}

std::string padRight(const std::string& s, std::size_t width) {
    const std::size_t w = console::visibleWidth(s);
    return w >= width ? s : s + std::string(width - w, ' ');
}

std::string composeBox(const Frame& logo, const std::vector<std::string>& panel, int logoCols, int panelCols) {
    const std::string border(console::kBlue);
    const std::string reset(console::kReset);
    std::string out;
    out += border + "┌" + repeat("─", logoCols + 2) + "┬" + repeat("─", panelCols + 2) + "┐" + reset + "\n";

    const std::size_t rows = std::max(logo.size(), panel.size());
    for (std::size_t r = 0; r < rows; ++r) {
        out += border + "│ " + reset;
        if (r < logo.size()) appendLogoRow(out, logo[r]);
        else out += std::string(static_cast<std::size_t>(logoCols), ' ');
        out += border + " │ " + reset;
        out += padRight(r < panel.size() ? panel[r] : std::string(), static_cast<std::size_t>(panelCols));
        out += border + " │" + reset + "\n";
    }
    out += border + "└" + repeat("─", logoCols + 2) + "┴" + repeat("─", panelCols + 2) + "┘" + reset + "\n";
    return out;
}

// Stellt sicher, dass der Cursor auch bei einer Exception wieder sichtbar wird.
struct CursorGuard {
    CursorGuard() { console::hideCursor(); }
    ~CursorGuard() { console::showCursor(); }
};

}  // namespace

// ---------------------------------------------------------------------------
// Oeffentliche Funktionen
// ---------------------------------------------------------------------------
std::optional<RgbaImage> loadImage(const fs::path& file) {
    // Ueber ifstream lesen statt stbi_load(): funktioniert unter Windows auch mit Umlauten im Pfad
    std::ifstream in(file, std::ios::binary);
    if (!in) return std::nullopt;
    const std::vector<unsigned char> bytes{std::istreambuf_iterator<char>(in), {}};
    if (bytes.empty()) return std::nullopt;

    int w = 0, h = 0, channels = 0;
    unsigned char* data = stbi_load_from_memory(bytes.data(), static_cast<int>(bytes.size()), &w, &h, &channels, 4);
    if (!data) {
        logWarn("Logo nicht lesbar (" + pathToUtf8(file) + "): " + stbi_failure_reason());
        return std::nullopt;
    }

    RgbaImage img;
    img.width = w;
    img.height = h;
    img.pixels.assign(data, data + static_cast<std::size_t>(w) * h * 4);
    stbi_image_free(data);
    for (std::size_t i = 3; i < img.pixels.size(); i += 4) {
        if (img.pixels[i] < 250) { img.hasAlpha = true; break; }
    }
    return img;
}

RgbaImage builtinLogo(int size) {
    RgbaImage img;
    img.width = img.height = size;
    img.hasAlpha = true;
    img.pixels.assign(static_cast<std::size_t>(size) * size * 4, 0);

    // Schild-Form: oben gerade, unten zu einer Spitze zulaufend
    auto halfWidth = [](double ny, double shrink) {
        const double top = -0.85 + shrink, bottom = 0.95 - shrink * 1.6;
        if (ny < top || ny > bottom) return -1.0;
        const double w = 0.78 - shrink;
        if (ny < 0.1) return w;
        const double t = (ny - 0.1) / (bottom - 0.1);
        return w * std::sqrt(std::max(0.0, 1.0 - t * t));
    };

    for (int y = 0; y < size; ++y) {
        for (int x = 0; x < size; ++x) {
            const double nx = (x + 0.5) / size * 2.0 - 1.0;
            const double ny = (y + 0.5) / size * 2.0 - 1.0;
            std::uint8_t* p = &img.pixels[(static_cast<std::size_t>(y) * size + x) * 4];

            const double outer = halfWidth(ny, 0.0);
            if (outer < 0 || std::abs(nx) > outer) continue;

            const double inner = halfWidth(ny, 0.1);
            const bool border = inner < 0 || std::abs(nx) > inner;

            // Schluesselloch: Kreis + Keil darunter
            const double dx = nx, dy = ny + 0.15;
            const bool keyhole = (dx * dx + dy * dy < 0.18 * 0.18) ||
                                 (ny > -0.15 && ny < 0.4 && std::abs(nx) < 0.07 + (ny + 0.15) * 0.12);

            if (border) {
                p[0] = 120; p[1] = 220; p[2] = 255;
            } else if (keyhole) {
                p[0] = 10; p[1] = 20; p[2] = 40;
            } else {
                const double t = (ny + 1.0) / 2.0;  // Verlauf oben -> unten
                p[0] = static_cast<std::uint8_t>(20 + 20 * t);
                p[1] = static_cast<std::uint8_t>(110 - 50 * t);
                p[2] = static_cast<std::uint8_t>(200 - 60 * t);
            }
            p[3] = 255;
        }
    }
    return img;
}

void removeBackground(RgbaImage& img) {
    if (img.hasAlpha || img.width < 4 || img.height < 4) return;

    // Hintergrund = Median der Randpixel (robust gegen Logo-Teile am Rand)
    std::vector<int> rs, gs, bs;
    auto sample = [&](int x, int y) {
        const std::uint8_t* p = pixelAt(img, x, y);
        rs.push_back(p[0]); gs.push_back(p[1]); bs.push_back(p[2]);
    };
    for (int x = 0; x < img.width; x += 2) { sample(x, 0); sample(x, img.height - 1); }
    for (int y = 0; y < img.height; y += 2) { sample(0, y); sample(img.width - 1, y); }
    auto median = [](std::vector<int>& v) {
        std::nth_element(v.begin(), v.begin() + static_cast<std::ptrdiff_t>(v.size() / 2), v.end());
        return v[v.size() / 2];
    };
    const int br = median(rs), bg = median(gs), bb = median(bs);

    // Abstand zur Hintergrundfarbe -> Deckkraft. Weiche Kante statt harter Schwelle,
    // damit Leuchteffekte ("Glow") sanft auslaufen. Leichtes Rauschen/Vignette faellt weg.
    constexpr double kStart = 40.0, kFull = 110.0;
    for (std::size_t i = 0; i < img.pixels.size(); i += 4) {
        const double dr = img.pixels[i] - br, dg = img.pixels[i + 1] - bg, db = img.pixels[i + 2] - bb;
        const double dist = std::sqrt(dr * dr + dg * dg + db * db);
        const double a = std::clamp((dist - kStart) / (kFull - kStart), 0.0, 1.0);
        img.pixels[i + 3] = static_cast<std::uint8_t>(a * 255.0);
    }
    img.hasAlpha = true;
}

RgbaImage cropToContent(const RgbaImage& img) {
    if (!img.hasAlpha) return img;
    int minX = img.width, minY = img.height, maxX = -1, maxY = -1;
    for (int y = 0; y < img.height; ++y) {
        for (int x = 0; x < img.width; ++x) {
            if (pixelAt(img, x, y)[3] < 96) continue;  // nur deutlich sichtbare Pixel zaehlen
            minX = std::min(minX, x); maxX = std::max(maxX, x);
            minY = std::min(minY, y); maxY = std::max(maxY, y);
        }
    }
    if (maxX < 0) return img;  // komplett leer

    // 3 % Rand lassen
    const int pad = std::max(1, static_cast<int>(0.03 * std::max(maxX - minX, maxY - minY)));
    minX = std::max(0, minX - pad); minY = std::max(0, minY - pad);
    maxX = std::min(img.width - 1, maxX + pad); maxY = std::min(img.height - 1, maxY + pad);

    RgbaImage out;
    out.width = maxX - minX + 1;
    out.height = maxY - minY + 1;
    out.hasAlpha = true;
    out.pixels.reserve(static_cast<std::size_t>(out.width) * out.height * 4);
    for (int y = minY; y <= maxY; ++y) {
        const std::uint8_t* row = pixelAt(img, minX, y);
        out.pixels.insert(out.pixels.end(), row, row + static_cast<std::size_t>(out.width) * 4);
    }
    return out;
}

RgbaImage downscale(const RgbaImage& src, int dw, int dh) {
    RgbaImage dst;
    dst.width = dw;
    dst.height = dh;
    dst.hasAlpha = src.hasAlpha;
    dst.pixels.assign(static_cast<std::size_t>(dw) * dh * 4, 0);
    if (src.width <= 0 || src.height <= 0) return dst;

    for (int dy = 0; dy < dh; ++dy) {
        const int y0 = static_cast<int>(std::floor(static_cast<double>(dy) * src.height / dh));
        const int y1 = std::max(y0 + 1, static_cast<int>(std::ceil(static_cast<double>(dy + 1) * src.height / dh)));
        for (int dx = 0; dx < dw; ++dx) {
            const int x0 = static_cast<int>(std::floor(static_cast<double>(dx) * src.width / dw));
            const int x1 = std::max(x0 + 1, static_cast<int>(std::ceil(static_cast<double>(dx + 1) * src.width / dw)));

            // Farben mit Alpha gewichten, sonst "bluten" transparente
            // (oft schwarze) Pixel als dunkler Rand in die Kanten.
            double sr = 0, sg = 0, sb = 0, sa = 0;
            int count = 0;
            for (int y = y0; y < std::min(y1, src.height); ++y) {
                for (int x = x0; x < std::min(x1, src.width); ++x) {
                    const std::uint8_t* p = pixelAt(src, x, y);
                    const double a = p[3] / 255.0;
                    sr += p[0] * a; sg += p[1] * a; sb += p[2] * a; sa += a;
                    ++count;
                }
            }
            std::uint8_t* d = &dst.pixels[(static_cast<std::size_t>(dy) * dw + dx) * 4];
            if (count == 0 || sa <= 0.0) continue;
            d[0] = static_cast<std::uint8_t>(std::clamp(sr / sa, 0.0, 255.0));
            d[1] = static_cast<std::uint8_t>(std::clamp(sg / sa, 0.0, 255.0));
            d[2] = static_cast<std::uint8_t>(std::clamp(sb / sa, 0.0, 255.0));
            d[3] = static_cast<std::uint8_t>(std::clamp(sa / count * 255.0, 0.0, 255.0));
        }
    }
    return dst;
}

Frame renderRotated(const RgbaImage& img, double angle, int cols, int rows) {
    // Zeichen von "leer" bis "voll"
    static constexpr std::string_view kRamp = " .:-=+*#%@";
    constexpr double kCameraDist = 3.0;  // kleiner = staerkere Perspektive
    constexpr double kMargin = 1.12;     // etwas Rand, damit die nahe Kante nicht abgeschnitten wird

    Frame frame(static_cast<std::size_t>(rows), std::vector<Cell>(static_cast<std::size_t>(cols)));
    const double c = std::cos(angle);
    const double s = std::sin(angle);
    // Licht kommt von vorne: je mehr die Flaeche zur Seite gedreht ist, desto dunkler
    const double light = 0.30 + 0.70 * std::abs(c);

    for (int cy = 0; cy < rows; ++cy) {
        const double sy = (((cy + 0.5) / rows) * 2.0 - 1.0) * kMargin;
        for (int cx = 0; cx < cols; ++cx) {
            const double sx = (((cx + 0.5) / cols) * 2.0 - 1.0) * kMargin;

            // Bildebene: Punkt (u, v, 0), um Y gedreht -> (u*c, v, u*s), Kamera im Abstand D.
            // Projektion:   sx = u*c*D / (D + u*s)
            // Nach u aufgeloest (Rueckwaerts-Abbildung Bildschirm -> Bild):
            const double denom = kCameraDist * c - sx * s;
            if (std::abs(denom) < 1e-6) continue;  // Bild steht genau seitlich
            const double u = sx * kCameraDist / denom;
            const double depth = kCameraDist + u * s;
            if (depth <= 0.1) continue;  // hinter der Kamera
            const double v = sy * depth / kCameraDist;
            if (u < -1.0 || u > 1.0 || v < -1.0 || v > 1.0) continue;

            const int px = static_cast<int>(std::lround((u + 1.0) * 0.5 * (img.width - 1)));
            const int py = static_cast<int>(std::lround((v + 1.0) * 0.5 * (img.height - 1)));
            const std::uint8_t* p = pixelAt(img, px, py);

            const double lum = luminance(p);
            double density = img.hasAlpha ? (p[3] / 255.0) * (0.55 + 0.45 * lum) : lum;
            density *= light;
            if (density < 0.05) continue;

            const auto idx = std::clamp(static_cast<int>(density * (kRamp.size() - 1) + 0.5), 1,
                                        static_cast<int>(kRamp.size() - 1));
            Cell& cell = frame[static_cast<std::size_t>(cy)][static_cast<std::size_t>(cx)];
            cell.ch = kRamp[static_cast<std::size_t>(idx)];

            // Sehr dunkle Logo-Farben auf schwarzem Terminal aufhellen
            const double maxCh = std::max({p[0], p[1], p[2], std::uint8_t{1}});
            const double boost = maxCh < 90 ? 90.0 / maxCh : 1.0;
            auto shade = [&](std::uint8_t ch) {
                return static_cast<std::uint8_t>(std::clamp(ch * boost * light, 0.0, 255.0));
            };
            cell.r = shade(p[0]);
            cell.g = shade(p[1]);
            cell.b = shade(p[2]);
        }
    }
    return frame;
}

void showIntro(const Config& cfg, bool animate) {
    RgbaImage source;
    if (auto loaded = loadImage(cfg.logoPath)) {
        source = std::move(*loaded);
        removeBackground(source);
        source = cropToContent(source);
    } else {
        logDebug("Kein Logo unter " + pathToUtf8(cfg.logoPath) + " - benutze eingebautes Logo");
        source = builtinLogo();
    }

    const std::vector<std::string> panel = panelLines();
    int panelCols = 0;
    for (const auto& l : panel) panelCols = std::max(panelCols, static_cast<int>(console::visibleWidth(l)));

    // Terminalzeichen sind etwa doppelt so hoch wie breit -> Faktor 2
    const int rows = static_cast<int>(panel.size());
    const double aspect = static_cast<double>(source.width) / std::max(1, source.height);
    // Breite Schriftzug-Logos (wie "YMU") bekommen bis zu 52 Spalten
    const int cols = std::clamp(static_cast<int>(std::lround(rows * 2.0 * aspect)), 16, 52);

    // 3-fache Aufloesung behalten, damit beim Drehen Details erhalten bleiben
    const RgbaImage small = downscale(source, cols * 3, rows * 3);

    const bool fits = console::terminalWidth() >= cols + panelCols + 8;
    auto draw = [&](double angle) {
        const Frame f = renderRotated(small, angle, cols, rows);
        std::string out;
        if (fits) {
            out = composeBox(f, panel, cols, panelCols);
        } else {
            // Zu schmal: Logo und Befehle untereinander
            for (const auto& row : f) { appendLogoRow(out, row); out += '\n'; }
            for (const auto& l : panel) out += l + '\n';
        }
        std::fwrite(out.data(), 1, out.size(), stdout);
        std::fflush(stdout);
    };

    if (!animate || cfg.introSeconds <= 0.0) {
        draw(0.0);
        return;
    }

    console::clearScreen();
    CursorGuard guard;
    using clock = std::chrono::steady_clock;
    constexpr int kFps = 30;
    constexpr double kTurns = 2.0;
    const int frames = std::max(1, static_cast<int>(cfg.introSeconds * kFps));
    const auto start = clock::now();

    for (int i = 0; i <= frames; ++i) {
        const double t = static_cast<double>(i) / frames;
        // Ease-out: schnell anfangen, sanft auslaufen und genau frontal stehen bleiben
        const double eased = 1.0 - std::pow(1.0 - t, 3.0);
        console::cursorHome();
        draw(eased * kTurns * 2.0 * std::numbers::pi);
        std::this_thread::sleep_until(start + std::chrono::milliseconds(1000 * (i + 1) / kFps));
    }
}

}  // namespace wt::ui
