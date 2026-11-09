#include "net/ServiceAudit.hpp"

#include "core/Console.hpp"

#include <algorithm>
#include <cctype>
#include <optional>
#include <regex>
#include <string>

namespace wt::net {
namespace {

struct PortRule {
    std::uint16_t port;
    Severity severity;
    std::string_view title;
    std::string_view advice;
};

// Regeln, die nur auf dem Port basieren.
constexpr PortRule kPortRules[] = {
    {23, Severity::Critical, "Telnet offen (unverschluesselt)",
     "Telnet abschalten und SSH verwenden."},
    {21, Severity::High, "FTP offen (Passwoerter im Klartext)",
     "SFTP/FTPS verwenden oder FTP deaktivieren."},
    {5900, Severity::High, "VNC offen", "VNC nur ueber VPN/SSH-Tunnel, starkes Passwort setzen."},
    {6379, Severity::High, "Redis offen (oft ohne Passwort)",
     "Redis an 127.0.0.1 binden und 'requirepass' setzen."},
    {27017, Severity::High, "MongoDB offen", "Authentifizierung aktivieren, nur lokal binden."},
    {445, Severity::Medium, "SMB-Freigabe erreichbar",
     "SMBv1 deaktivieren, Freigaben pruefen, nie ins Internet weiterleiten."},
    {139, Severity::Medium, "NetBIOS erreichbar", "NetBIOS ueber TCP/IP deaktivieren, falls nicht benoetigt."},
    {3389, Severity::Medium, "Remote Desktop erreichbar",
     "Network Level Authentication aktivieren, nicht ins Internet weiterleiten."},
    {1883, Severity::Medium, "MQTT ohne TLS", "MQTT ueber TLS (Port 8883) mit Login betreiben."},
    {512, Severity::High, "rexec offen (veraltet, unverschluesselt)", "Dienst abschalten, SSH verwenden."},
    {513, Severity::High, "rlogin offen (veraltet, unverschluesselt)", "Dienst abschalten, SSH verwenden."},
    {514, Severity::High, "rsh offen (veraltet, unverschluesselt)", "Dienst abschalten, SSH verwenden."},
    {69, Severity::Medium, "TFTP-Port offen (ohne Login)", "TFTP nur bei Bedarf aktivieren."},
    {110, Severity::Low, "POP3 ohne TLS", "POP3S (Port 995) verwenden."},
    {143, Severity::Low, "IMAP ohne TLS", "IMAPS (Port 993) verwenden."},
    {161, Severity::Medium, "SNMP-Port offen", "Standard-Community 'public' aendern oder SNMPv3 nutzen."},
    {1433, Severity::Medium, "MS-SQL offen", "Nur aus dem noetigen Netz erreichbar machen."},
    {3306, Severity::Medium, "MySQL/MariaDB offen", "An 127.0.0.1 binden, wenn nur lokal benoetigt."},
    {5432, Severity::Medium, "PostgreSQL offen", "listen_addresses und pg_hba.conf pruefen."},
    {2375, Severity::Critical, "Docker-API ohne TLS", "Docker-API niemals ungeschuetzt freigeben - Root-Zugriff!"},
    {9200, Severity::High, "Elasticsearch offen", "Security-Features aktivieren, nur lokal binden."},
    {11211, Severity::High, "Memcached offen", "An 127.0.0.1 binden."},
    {5555, Severity::High, "Android-Debug (ADB) offen", "USB-/WLAN-Debugging auf dem Geraet abschalten."},
    {9100, Severity::Low, "Drucker-Rohdatenport offen", "Nur aus dem LAN erreichbar machen."},
    {631, Severity::Low, "Druckdienst (IPP/CUPS) erreichbar", "Nur im LAN freigeben, Firmware aktuell halten."},
    {8291, Severity::Medium, "MikroTik Winbox erreichbar", "Nur aus dem Admin-Netz erlauben, RouterOS aktualisieren."},
    {7547, Severity::High, "TR-069-Fernwartung des Routers offen", "Fernwartung im Router deaktivieren."},
};

// Liest "OpenSSH_7.4" -> {7, 4}
std::optional<std::pair<int, int>> openSshVersion(const std::string& banner) {
    static const std::regex re(R"(OpenSSH_(\d+)\.(\d+))");
    std::smatch m;
    if (!std::regex_search(banner, m, re)) return std::nullopt;
    return std::pair{std::stoi(m[1].str()), std::stoi(m[2].str())};
}

bool containsCaseInsensitive(std::string_view hay, std::string_view needle) {
    auto it = std::search(hay.begin(), hay.end(), needle.begin(), needle.end(), [](char a, char b) {
        return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
    });
    return it != hay.end();
}

void bannerRules(const HostScan& scan, const PortResult& p, std::vector<Finding>& out) {
    const std::string& b = p.banner;
    if (b.empty()) return;

    if (b.rfind("SSH-1.", 0) == 0) {
        out.push_back({Severity::Critical, scan.ipText, p.port, "SSH-Protokoll Version 1",
                       "SSHv1 ist gebrochen - nur SSHv2 erlauben."});
    }
    if (auto v = openSshVersion(b); v && (v->first < 8 || (v->first == 8 && v->second < 5))) {
        out.push_back({Severity::Medium, scan.ipText, p.port,
                       "Veraltetes OpenSSH " + std::to_string(v->first) + "." + std::to_string(v->second),
                       "OpenSSH aktualisieren (bekannte Schwachstellen in alten Versionen)."});
    }
    if (containsCaseInsensitive(b, "vsFTPd 2.3.4")) {
        out.push_back({Severity::Critical, scan.ipText, p.port, "vsFTPd 2.3.4 (bekannte Hintertuer)",
                       "Sofort aktualisieren oder Dienst abschalten."});
    }
    // HTTP-Server, die ihre genaue Version verraten (z. B. "Server: Apache/2.4.29")
    static const std::regex versionRe(R"(^Server:\s*\S+/\d+(\.\d+)+)", std::regex::icase);
    if (std::regex_search(b, versionRe)) {
        out.push_back({Severity::Low, scan.ipText, p.port, "Webserver verraet Versionsnummer (" + b + ")",
                       "Versionsangabe im Server-Header ausblenden (z. B. ServerTokens Prod)."});
    }
}

}  // namespace

std::vector<Finding> auditHost(const HostScan& scan) {
    std::vector<Finding> findings;

    auto isOpen = [&](std::uint16_t port) {
        return std::any_of(scan.openPorts.begin(), scan.openPorts.end(),
                           [port](const PortResult& p) { return p.port == port; });
    };

    for (const auto& p : scan.openPorts) {
        for (const auto& rule : kPortRules) {
            if (rule.port == p.port) {
                findings.push_back({rule.severity, scan.ipText, p.port, std::string(rule.title),
                                    std::string(rule.advice)});
            }
        }
        bannerRules(scan, p, findings);
    }

    // Kombinationsregel: Webinterface nur ueber HTTP, kein HTTPS
    if ((isOpen(80) || isOpen(8080)) && !isOpen(443) && !isOpen(8443)) {
        findings.push_back({Severity::Low, scan.ipText, static_cast<std::uint16_t>(isOpen(80) ? 80 : 8080),
                            "Webinterface ohne HTTPS",
                            "Passwoerter werden unverschluesselt uebertragen - HTTPS aktivieren."});
    }

    std::sort(findings.begin(), findings.end(),
              [](const Finding& a, const Finding& b) { return a.severity > b.severity; });
    return findings;
}

std::string_view severityName(Severity s) {
    switch (s) {
        case Severity::Info: return "INFO";
        case Severity::Low: return "NIEDRIG";
        case Severity::Medium: return "MITTEL";
        case Severity::High: return "HOCH";
        case Severity::Critical: return "KRITISCH";
    }
    return "?";
}

std::string_view severityColor(Severity s) {
    switch (s) {
        case Severity::Info: return console::kGray;
        case Severity::Low: return console::kCyan;
        case Severity::Medium: return console::kYellow;
        case Severity::High: return console::kRed;
        case Severity::Critical: return console::kMagenta;
    }
    return console::kReset;
}

}  // namespace wt::net
