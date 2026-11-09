# Wachturm

[![Build und Tests](https://github.com/helloo970/wachturm/actions/workflows/build.yml/badge.svg)](https://github.com/helloo970/wachturm/actions/workflows/build.yml)
![C++20](https://img.shields.io/badge/C%2B%2B-20-blue)
![Plattform](https://img.shields.io/badge/Plattform-Windows%20%7C%20Linux-lightgrey)
[![Lizenz: MIT](https://img.shields.io/badge/Lizenz-MIT-green)](LICENSE)

Sicherheits-Suite fürs Heimnetz (C++20, Windows + Linux):

- **Host-Discovery**: findet Geräte per parallelem TCP-Sweep und ARP
- **Port-Scanner**: Thread-Pool, Banner-Grabbing, Dienst-Erkennung
- **Unsichere Dienste**: Telnet, FTP, SMB, altes OpenSSH, vsFTPd-Backdoor …
- **File-Integrity**: SHA-256-Baseline, erkennt neue/geänderte/gelöschte Dateien
- **Malware-Erkennung**: Hash-Blacklist, YARA, Entropie, getarnte Endungen
- **Quarantäne**: zlib + AES-256-GCM, automatisch, mit Wiederherstellung
- **Intro**: dein PNG-Logo dreht sich in 3D, daneben die 5 wichtigsten Befehle

> Nur auf eigenen Geräten und im eigenen Netz verwenden.

## Herunterladen

Fertige Windows-Version: unter [Releases](https://github.com/helloo970/wachturm/releases)
die `Wachturm.zip` laden, entpacken und im Ordner `.\wachturm.exe` starten.
Alle Dateien im Ordner müssen zusammenbleiben.

Jeder Push baut das Programm automatisch (GitHub Actions). Das Paket liegt dann im
jeweiligen Lauf unter *Artifacts*.

## Bauen (Windows, Visual Studio 2022)

```bash
git clone https://github.com/helloo970/wachturm.git
```

1. vcpkg installieren (falls nicht vorhanden):
   ```bash
   git clone https://github.com/microsoft/vcpkg C:/vcpkg
   ```
   ```bash
   C:/vcpkg/bootstrap-vcpkg.bat
   ```
   Umgebungsvariable `VCPKG_ROOT=C:\vcpkg` setzen.
2. Visual Studio → *Ordner öffnen* → `wachturm`. VS erkennt `CMakePresets.json`,
   vcpkg installiert alle Bibliotheken automatisch (dauert beim ersten Mal).
3. Preset `windows-debug` wählen → *Alles erstellen*.

Kommandozeile (Developer PowerShell):
```bash
cmake --preset windows-release
```
```bash
cmake --build build/windows-release --config Release
```

Ohne YARA bauen (falls libyara Probleme macht): in `vcpkg.json` die Zeile
`"default-features": [ "yara" ]` entfernen.

## Logo

Dein Logo als `logo.png` in den Projektordner `wachturm/` legen. Beim Bauen wird
es automatisch neben die `wachturm.exe` kopiert (oder `logo_path` in `config.json`).

- Transparenter Hintergrund ist nicht nötig: Bei Logos auf einfarbigem Hintergrund
  (z. B. schwarz) wird der Hintergrund automatisch entfernt.
- Leere Ränder werden abgeschnitten, damit das Logo den Kasten füllt.
- Breite Schriftzüge bekommen bis zu 52 Zeichen Breite. Das Terminal sollte dann
  mindestens ~95 Zeichen breit sein, sonst stehen Logo und Befehle untereinander.
- Ohne Datei wird ein eingebautes Schild angezeigt.

## Benutzung

```bash
wachturm
```
```bash
wachturm discover 192.168.178.0/24
```
```bash
wachturm audit 192.168.178.0/24 --html
```
```bash
wachturm baseline C:/Users/du/Downloads
```
```bash
wachturm check --update
```
```bash
wachturm quarantine list
```
```bash
wachturm quarantine restore <id>
```

Exit-Codes: `0` = alles ok, `1` = Fehler, `2` = Probleme gefunden.

### So funktioniert die Quarantäne

Jede neue oder geänderte Datei bekommt Punkte (Gewichte in `config.json`):

| Merkmal                                  | Punkte |
|------------------------------------------|-------:|
| Hash auf der Blacklist                   | 100 |
| YARA-Regel trifft                        | 80 |
| Doppelte Endung (`rechnung.pdf.exe`)     | 50 |
| Ausführbar + Entropie ≥ 7.2 (gepackt)    | 40 |
| Neu/geändert seit Baseline               | 20 |

Ab **80 Punkten** wird die Datei automatisch verschoben. Eine einfach nur neue
Datei (20) oder ein neues, gepacktes Installationsprogramm (60) wird **nicht**
verschoben, nur gemeldet. Dateien in Systemordnern (`C:\Windows`, `/usr` …)
werden nie automatisch verschoben. `--no-quarantine` schaltet das Verschieben ab.

Das Original wird erst gelöscht, nachdem die Quarantäne-Datei zurückgelesen und
per SHA-256 geprüft wurde.

## Anpassen

- Slogan und die 5 Befehle im Kasten: `src/ui/Banner.cpp` (`kTagline`, `kTopCommands`)
- Regeln für unsichere Dienste: `src/net/ServiceAudit.cpp` (`kPortRules`)
- Eigene YARA-Regeln: einfach weitere `.yar`-Dateien in den Ordner `rules/` legen
- Bekannte Schadsoftware-Hashes: `blacklist.txt` (auch `sha256sum`-Format geht)

### Testen mit EICAR

Die EICAR-Datei ist eine harmlose Testdatei, die jeder Virenscanner kennt.
Lege eine Datei `eicar.com.txt` mit diesem Inhalt in einen Testordner, **nachdem**
du dort `wachturm baseline` ausgeführt hast:
```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```
`wachturm check` sollte sie per YARA und per Hash-Blacklist finden
und in die Quarantäne verschieben. Windows Defender schlägt
dabei wahrscheinlich auch Alarm. Das ist normal.

## Projektaufbau

```
src/core/        Konfiguration, Logger, Thread-Pool, Konsole
src/net/         Sockets, Host-Discovery, Port-Scanner, Dienst-Bewertung
src/fim/         SHA-256, Entropie, Baseline, YARA, Erkennung
src/quarantine/  Verschlüsselte Quarantäne (zlib + AES-256-GCM)
src/report/      Konsolen-, JSON- und HTML-Berichte
src/ui/          3D-Logo-Intro, Fortschrittsbalken
tests/           Catch2-Tests
rules/           YARA-Regeln
config/          config.json, blacklist.txt
gui-demo.html    Klickbare Vorschau einer möglichen grafischen Oberfläche
```

## Lizenz

MIT, siehe [LICENSE](LICENSE).
