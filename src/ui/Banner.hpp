#pragma once
// Start-Banner: Logo (PNG) dreht sich in 3D um die senkrechte Achse,
// rechts daneben ein Kasten mit den 5 wichtigsten Befehlen.

#include "core/Config.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <vector>

namespace wt::ui {

struct RgbaImage {
    int width = 0;
    int height = 0;
    std::vector<std::uint8_t> pixels;  // RGBA, zeilenweise
    bool hasAlpha = false;             // true, wenn es transparente Pixel gibt
};

// PNG/JPG laden (stb_image). nullopt, wenn Datei fehlt oder kaputt ist.
std::optional<RgbaImage> loadImage(const std::filesystem::path& file);

// Eingebautes Ersatz-Logo (Schild mit Schluesselloch), solange kein logo.png da ist.
RgbaImage builtinLogo(int size = 128);

// Bilder ohne Transparenz (z. B. Logo auf schwarzem Hintergrund):
// Hintergrundfarbe aus den Bildraendern schaetzen und durchsichtig machen.
void removeBackground(RgbaImage& img);

// Leere/durchsichtige Raender abschneiden, damit das Logo den Platz fuellt.
RgbaImage cropToContent(const RgbaImage& img);

// Hochwertiges Verkleinern (Box-Filter mit vormultipliziertem Alpha).
RgbaImage downscale(const RgbaImage& src, int width, int height);

struct Cell {
    char ch = ' ';
    std::uint8_t r = 0, g = 0, b = 0;
};
using Frame = std::vector<std::vector<Cell>>;

// Zeichnet das Bild als ASCII, um 'angle' (Radiant) um die Y-Achse gedreht,
// mit Perspektive und Beleuchtung.
Frame renderRotated(const RgbaImage& img, double angle, int cols, int rows);

// Zeigt das Intro. animate = false -> nur das stehende Endbild.
void showIntro(const Config& cfg, bool animate);

}  // namespace wt::ui
