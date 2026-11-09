// Winsock MUSS vor windows.h eingebunden werden - deshalb ganz oben.
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "net/Socket.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <stdexcept>

namespace wt::net {

using Clock = std::chrono::steady_clock;
using std::chrono::milliseconds;

// ---------------------------------------------------------------------------
// Plattform-Abstraktion
// ---------------------------------------------------------------------------
namespace {

#ifdef _WIN32
using socket_t = SOCKET;
using sock_len_t = int;
constexpr socket_t kInvalidSocket = INVALID_SOCKET;
constexpr int kSendFlags = 0;
int lastError() { return WSAGetLastError(); }
void closeSocket(socket_t s) { ::closesocket(s); }
bool isInProgress(int e) { return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS; }
bool isRefused(int e) { return e == WSAECONNREFUSED; }
bool isTimeout(int e) { return e == WSAETIMEDOUT; }
#else
using socket_t = int;
using sock_len_t = socklen_t;
constexpr socket_t kInvalidSocket = -1;
#ifdef MSG_NOSIGNAL
constexpr int kSendFlags = MSG_NOSIGNAL;  // kein SIGPIPE bei geschlossener Verbindung
#else
constexpr int kSendFlags = 0;
#endif
int lastError() { return errno; }
void closeSocket(socket_t s) { ::close(s); }
bool isInProgress(int e) { return e == EINPROGRESS || e == EWOULDBLOCK; }
bool isRefused(int e) { return e == ECONNREFUSED; }
bool isTimeout(int e) { return e == ETIMEDOUT; }
#endif

// RAII-Huelle: Socket wird immer geschlossen, auch bei Exceptions.
class Socket {
public:
    Socket() = default;
    explicit Socket(socket_t s) : s_(s) {}
    ~Socket() { reset(); }
    Socket(Socket&& o) noexcept : s_(o.s_) { o.s_ = kInvalidSocket; }
    Socket& operator=(Socket&& o) noexcept {
        if (this != &o) { reset(); s_ = o.s_; o.s_ = kInvalidSocket; }
        return *this;
    }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;

    socket_t get() const { return s_; }
    bool valid() const { return s_ != kInvalidSocket; }
    void reset() { if (valid()) { closeSocket(s_); s_ = kInvalidSocket; } }

private:
    socket_t s_ = kInvalidSocket;
};

bool setNonBlocking(socket_t s) {
#ifdef _WIN32
    u_long mode = 1;
    return ::ioctlsocket(s, FIONBIO, &mode) == 0;
#else
    const int flags = ::fcntl(s, F_GETFL, 0);
    return flags >= 0 && ::fcntl(s, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

timeval toTimeval(milliseconds ms) {
    if (ms.count() < 0) ms = milliseconds(0);
    timeval tv{};
    tv.tv_sec = static_cast<decltype(tv.tv_sec)>(ms.count() / 1000);
    tv.tv_usec = static_cast<decltype(tv.tv_usec)>((ms.count() % 1000) * 1000);
    return tv;
}

sockaddr_in makeAddr(std::uint32_t ip, std::uint16_t port) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(ip);
    return addr;
}

PortState classifyError(int err) {
    if (isRefused(err)) return PortState::Closed;
    if (isTimeout(err)) return PortState::Filtered;
    return PortState::Unreachable;
}

// Wartet, bis s lesbar ist. >0 = lesbar, 0 = Timeout, <0 = Fehler
int waitReadable(socket_t s, milliseconds timeout) {
    fd_set rset;
    FD_ZERO(&rset);
    FD_SET(s, &rset);
    timeval tv = toTimeval(timeout);
#ifdef _WIN32
    return ::select(0, &rset, nullptr, nullptr, &tv);
#else
    return ::select(s + 1, &rset, nullptr, nullptr, &tv);
#endif
}

// Liest den SO_ERROR eines Sockets nach einem nicht-blockierenden connect().
int pendingSocketError(socket_t s) {
    int soErr = 0;
    sock_len_t len = sizeof(soErr);
    if (::getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soErr), &len) != 0) {
        return lastError();
    }
    return soErr;
}

bool isHttpLikePort(std::uint16_t port) {
    static constexpr std::array<std::uint16_t, 8> kHttp{80, 81, 5000, 8000, 8008, 8080, 8081, 8888};
    return std::find(kHttp.begin(), kHttp.end(), port) != kHttp.end();
}

// Steuerzeichen raus, auf eine sinnvolle Zeile kuerzen.
std::string cleanBanner(const std::string& raw, bool http) {
    std::string text = raw;
    if (http) {
        // Bei HTTP ist der "Server:"-Header interessanter als die Statuszeile.
        std::string lower = raw;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (auto pos = lower.find("\nserver:"); pos != std::string::npos) {
            auto end = raw.find('\n', pos + 1);
            text = raw.substr(pos + 1, end == std::string::npos ? std::string::npos : end - pos - 1);
        }
    }
    if (auto nl = text.find('\n'); nl != std::string::npos) text.resize(nl);

    std::string out;
    out.reserve(text.size());
    for (unsigned char c : text) {
        out.push_back((c >= 0x20 && c < 0x7f) ? static_cast<char>(c) : ' ');
    }
    // Trimmen
    const auto first = out.find_first_not_of(' ');
    if (first == std::string::npos) return {};
    const auto last = out.find_last_not_of(' ');
    out = out.substr(first, last - first + 1);
    if (out.size() > 120) out.resize(120);
    return out;
}

std::string grabBanner(socket_t s, std::uint16_t port, milliseconds timeout) {
    const bool http = isHttpLikePort(port);
    if (http) {
        static constexpr char kRequest[] = "HEAD / HTTP/1.0\r\nUser-Agent: Wachturm\r\n\r\n";
        ::send(s, kRequest, static_cast<int>(sizeof(kRequest) - 1), kSendFlags);
    }

    std::string data;
    std::array<char, 512> buf{};
    const auto deadline = Clock::now() + timeout;
    while (data.size() < 2048) {
        const auto remaining = std::chrono::duration_cast<milliseconds>(deadline - Clock::now());
        if (remaining.count() <= 0) break;
        if (waitReadable(s, remaining) <= 0) break;
        const int n = ::recv(s, buf.data(), static_cast<int>(buf.size()), 0);
        if (n <= 0) break;
        data.append(buf.data(), static_cast<std::size_t>(n));
        // Ohne HTTP reicht die erste Zeile (SSH, FTP, SMTP ...), bei HTTP der Header.
        if (!http && data.find('\n') != std::string::npos) break;
        if (http && data.find("\r\n\r\n") != std::string::npos) break;
    }
    return cleanBanner(data, http);
}

}  // namespace

// ---------------------------------------------------------------------------
// Oeffentliche API
// ---------------------------------------------------------------------------
NetworkSession::NetworkSession() {
#ifdef _WIN32
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
        throw std::runtime_error("WSAStartup fehlgeschlagen");
    }
#endif
}

NetworkSession::~NetworkSession() {
#ifdef _WIN32
    WSACleanup();
#endif
}

std::string_view portStateName(PortState s) {
    switch (s) {
        case PortState::Open: return "offen";
        case PortState::Closed: return "geschlossen";
        case PortState::Filtered: return "gefiltert";
        case PortState::Unreachable: return "unerreichbar";
    }
    return "?";
}

ProbeResult probeTcp(std::uint32_t ip, std::uint16_t port, milliseconds connectTimeout,
                     std::optional<milliseconds> bannerTimeout) {
    ProbeResult result;
    Socket sock(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    if (!sock.valid() || !setNonBlocking(sock.get())) {
        result.state = PortState::Unreachable;
        return result;
    }

    const sockaddr_in addr = makeAddr(ip, port);
    const auto start = Clock::now();
    const int rc = ::connect(sock.get(), reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));

    if (rc != 0) {
        const int err = lastError();
        if (!isInProgress(err)) {
            result.state = classifyError(err);
            return result;
        }

        // Nicht-blockierender connect laeuft -> auf "schreibbar" (Erfolg)
        // oder "exception" (Windows meldet Fehlschlag dort) warten.
        fd_set wset, eset;
        FD_ZERO(&wset);
        FD_ZERO(&eset);
        FD_SET(sock.get(), &wset);
        FD_SET(sock.get(), &eset);
        timeval tv = toTimeval(connectTimeout);
#ifdef _WIN32
        const int n = ::select(0, nullptr, &wset, &eset, &tv);
#else
        const int n = ::select(sock.get() + 1, nullptr, &wset, &eset, &tv);
#endif
        result.rtt = std::chrono::duration_cast<milliseconds>(Clock::now() - start);
        if (n == 0) { result.state = PortState::Filtered; return result; }
        if (n < 0)  { result.state = PortState::Unreachable; return result; }

        const int soErr = pendingSocketError(sock.get());
        if (soErr != 0) {
            result.state = classifyError(soErr);
            return result;
        }
    } else {
        result.rtt = std::chrono::duration_cast<milliseconds>(Clock::now() - start);
    }

    result.state = PortState::Open;
    if (bannerTimeout) result.banner = grabBanner(sock.get(), port, *bannerTimeout);
    return result;
}

std::optional<AliveHit> firstResponsivePort(std::uint32_t ip, const std::vector<std::uint16_t>& ports,
                                            milliseconds timeout) {
    struct Pending {
        Socket sock;
        std::uint16_t port;
    };
    std::vector<Pending> pending;
    // FD_SETSIZE ist unter Windows standardmaessig 64.
    const std::size_t maxPorts = std::min<std::size_t>(ports.size(), 60);
    pending.reserve(maxPorts);

    const auto start = Clock::now();
    for (std::size_t i = 0; i < maxPorts; ++i) {
        Socket s(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
        if (!s.valid() || !setNonBlocking(s.get())) continue;
        const sockaddr_in addr = makeAddr(ip, ports[i]);
        const int rc = ::connect(s.get(), reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
        if (rc == 0) {
            return AliveHit{ports[i], PortState::Open,
                            std::chrono::duration_cast<milliseconds>(Clock::now() - start)};
        }
        const int err = lastError();
        if (isRefused(err)) {
            return AliveHit{ports[i], PortState::Closed,
                            std::chrono::duration_cast<milliseconds>(Clock::now() - start)};
        }
        if (isInProgress(err)) pending.push_back({std::move(s), ports[i]});
    }

    const auto deadline = start + timeout;
    while (!pending.empty()) {
        const auto remaining = std::chrono::duration_cast<milliseconds>(deadline - Clock::now());
        if (remaining.count() <= 0) break;

        fd_set wset, eset;
        FD_ZERO(&wset);
        FD_ZERO(&eset);
        socket_t maxFd = 0;
        for (auto& p : pending) {
            FD_SET(p.sock.get(), &wset);
            FD_SET(p.sock.get(), &eset);
            maxFd = std::max(maxFd, p.sock.get());
        }
        timeval tv = toTimeval(remaining);
#ifdef _WIN32
        (void)maxFd;
        const int n = ::select(0, nullptr, &wset, &eset, &tv);
#else
        const int n = ::select(maxFd + 1, nullptr, &wset, &eset, &tv);
#endif
        if (n <= 0) break;

        // Fertige Sockets auswerten; nicht-antwortende bleiben in der Liste.
        for (auto it = pending.begin(); it != pending.end();) {
            const socket_t s = it->sock.get();
            if (!FD_ISSET(s, &wset) && !FD_ISSET(s, &eset)) { ++it; continue; }
            const int soErr = pendingSocketError(s);
            const auto rtt = std::chrono::duration_cast<milliseconds>(Clock::now() - start);
            if (soErr == 0) return AliveHit{it->port, PortState::Open, rtt};
            if (isRefused(soErr)) return AliveHit{it->port, PortState::Closed, rtt};
            it = pending.erase(it);  // anderer Fehler -> dieser Port sagt nichts
        }
    }
    return std::nullopt;
}

std::optional<std::uint32_t> resolveIpv4(const std::string& host) {
    in_addr direct{};
    if (::inet_pton(AF_INET, host.c_str(), &direct) == 1) return ntohl(direct.s_addr);

    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (::getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || res == nullptr) return std::nullopt;

    std::optional<std::uint32_t> ip;
    for (addrinfo* p = res; p != nullptr; p = p->ai_next) {
        if (p->ai_family == AF_INET) {
            ip = ntohl(reinterpret_cast<sockaddr_in*>(p->ai_addr)->sin_addr.s_addr);
            break;
        }
    }
    ::freeaddrinfo(res);
    return ip;
}

std::string reverseLookup(std::uint32_t ip) {
    const sockaddr_in addr = makeAddr(ip, 0);
    char host[NI_MAXHOST] = {};
    // NI_NAMEREQD: lieber leer als die IP noch einmal als "Name"
    const int rc = ::getnameinfo(reinterpret_cast<const sockaddr*>(&addr), sizeof(addr), host, sizeof(host),
                                 nullptr, 0, NI_NAMEREQD);
    return rc == 0 ? std::string(host) : std::string();
}

}  // namespace wt::net
