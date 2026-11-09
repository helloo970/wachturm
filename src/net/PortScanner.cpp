#include "net/PortScanner.hpp"

#include "core/Logger.hpp"
#include "net/Targets.hpp"

#include <algorithm>
#include <atomic>
#include <future>
#include <utility>

namespace wt::net {

std::string_view serviceName(std::uint16_t port) {
    static constexpr std::pair<std::uint16_t, std::string_view> kServices[] = {
        {20, "ftp-data"},   {21, "ftp"},          {22, "ssh"},         {23, "telnet"},
        {25, "smtp"},       {53, "dns"},          {67, "dhcp"},        {69, "tftp"},
        {80, "http"},       {81, "http-alt"},     {88, "kerberos"},    {110, "pop3"},
        {111, "rpcbind"},   {119, "nntp"},        {123, "ntp"},        {135, "msrpc"},
        {137, "netbios-ns"},{139, "netbios"},     {143, "imap"},       {161, "snmp"},
        {389, "ldap"},      {443, "https"},       {445, "smb"},        {465, "smtps"},
        {512, "rexec"},     {513, "rlogin"},      {514, "rsh"},        {515, "lpd"},
        {548, "afp"},       {554, "rtsp"},        {587, "submission"}, {631, "ipp"},
        {636, "ldaps"},     {853, "dns-over-tls"},{873, "rsync"},      {993, "imaps"},
        {995, "pop3s"},     {1194, "openvpn"},    {1433, "mssql"},     {1723, "pptp"},
        {1883, "mqtt"},     {1900, "upnp"},       {2049, "nfs"},       {2375, "docker"},
        {2376, "docker-tls"},{3000, "http-dev"},  {3306, "mysql"},     {3389, "rdp"},
        {5000, "upnp/http"},{5060, "sip"},        {5353, "mdns"},      {5432, "postgres"},
        {5555, "adb"},      {5900, "vnc"},        {6379, "redis"},     {7547, "tr-069"},
        {8000, "http-alt"}, {8008, "http-alt"},   {8080, "http-proxy"},{8081, "http-alt"},
        {8123, "home-assistant"}, {8291, "winbox"}, {8443, "https-alt"}, {8883, "mqtt-tls"},
        {8888, "http-alt"}, {9000, "http-alt"},   {9100, "jetdirect"}, {9200, "elasticsearch"},
        {11211, "memcached"}, {27017, "mongodb"}, {32400, "plex"},     {49152, "upnp"},
        {62078, "iphone-sync"},
    };
    for (const auto& [p, name] : kServices) {
        if (p == port) return name;
    }
    return "";
}

HostScan PortScanner::scan(std::uint32_t ip, const std::vector<std::uint16_t>& ports, const ProgressFn& progress) {
    const auto connectTimeout = std::chrono::milliseconds(cfg_.connectTimeoutMs);
    const auto bannerTimeout = std::chrono::milliseconds(cfg_.bannerTimeoutMs);

    HostScan result;
    result.ip = ip;
    result.ipText = ipv4ToString(ip);
    logInfo("Portscan " + result.ipText + ": " + std::to_string(ports.size()) + " Ports");

    std::atomic<std::size_t> done{0};
    std::vector<std::future<PortResult>> futures;
    futures.reserve(ports.size());

    for (const auto port : ports) {
        futures.push_back(pool_.submit([=, &done, &progress, total = ports.size()] {
            PortResult r;
            r.port = port;
            const ProbeResult probe = probeTcp(ip, port, connectTimeout, bannerTimeout);
            r.state = probe.state;
            r.rtt = probe.rtt;
            r.banner = probe.banner;
            r.service = std::string(serviceName(port));
            const auto n = ++done;
            if (progress) progress(n, total);
            return r;
        }));
    }

    for (auto& f : futures) {
        PortResult r = f.get();
        switch (r.state) {
            case PortState::Open: result.openPorts.push_back(std::move(r)); break;
            case PortState::Closed: ++result.closed; break;
            default: ++result.filtered; break;
        }
    }
    std::sort(result.openPorts.begin(), result.openPorts.end(),
              [](const PortResult& a, const PortResult& b) { return a.port < b.port; });

    logInfo("Portscan " + result.ipText + " fertig: " + std::to_string(result.openPorts.size()) + " offen");
    return result;
}

}  // namespace wt::net
