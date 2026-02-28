#include "netwrap.h"
#include <cstring>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  #include <io.h>
  #include <fcntl.h>
  #include <unordered_map>
  #include <mutex>

  static std::mutex g_mtx;
  static std::unordered_map<int, SOCKET> g_fd2sock;

  static int sock_to_fd(SOCKET s) {
    int fd = _open_osfhandle((intptr_t)s, 0);
    if (fd < 0) return -1;
    std::lock_guard<std::mutex> lk(g_mtx);
    g_fd2sock[fd] = s;
    return fd;
  }

  static SOCKET fd_to_sock(int fd) {
    std::lock_guard<std::mutex> lk(g_mtx);
    auto it = g_fd2sock.find(fd);
    if (it == g_fd2sock.end()) return INVALID_SOCKET;
    return it->second;
  }

  static void erase_fd(int fd) {
    std::lock_guard<std::mutex> lk(g_mtx);
    g_fd2sock.erase(fd);
  }
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <errno.h>
#endif

static bool resolve_ipv4(const char* host, in_addr* out_addr) {
  if (inet_pton(AF_INET, host, out_addr) == 1) return true;

  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;

  addrinfo* res = nullptr;
  int rc = getaddrinfo(host, nullptr, &hints, &res);
  if (rc != 0 || !res) return false;

  sockaddr_in* a = (sockaddr_in*)res->ai_addr;
  *out_addr = a->sin_addr;
  freeaddrinfo(res);
  return true;
}

extern "C" {

bool net_init() {
#ifdef _WIN32
  static bool inited = false;
  if (inited) return true;
  WSADATA wsa{};
  if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) return false;
  inited = true;
#endif
  return true;
}

int udp_socket_ipv4_fd() {
#ifdef _WIN32
  SOCKET s = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (s == INVALID_SOCKET) return -1;
  return sock_to_fd(s);
#else
  return ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
#endif
}

bool sock_bind_any_ipv4_fd(int fd, uint16_t port) {
#ifdef _WIN32
  SOCKET s = fd_to_sock(fd);
  if (s == INVALID_SOCKET) return false;
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  return ::bind(s, (sockaddr*)&addr, sizeof(addr)) == 0;
#else
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  return ::bind(fd, (sockaddr*)&addr, sizeof(addr)) == 0;
#endif
}

bool sock_connect_ipv4_fd(int fd, const char* host, uint16_t port) {
#ifdef _WIN32
  SOCKET s = fd_to_sock(fd);
  if (s == INVALID_SOCKET) return false;

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (!resolve_ipv4(host, &addr.sin_addr)) return false;
  return ::connect(s, (sockaddr*)&addr, sizeof(addr)) == 0;
#else
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (!resolve_ipv4(host, &addr.sin_addr)) return false;
  return ::connect(fd, (sockaddr*)&addr, sizeof(addr)) == 0;
#endif
}

bool sock_set_nonblock_fd(int fd) {
#ifdef _WIN32
  SOCKET s = fd_to_sock(fd);
  if (s == INVALID_SOCKET) return false;
  u_long mode = 1;
  return ioctlsocket(s, FIONBIO, &mode) == 0;
#else
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) return false;
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

void sock_close_fd(int fd) {
#ifdef _WIN32
  SOCKET s = fd_to_sock(fd);
  if (s != INVALID_SOCKET) {
    closesocket(s);
    erase_fd(fd);
  }
  _close(fd);
#else
  close(fd);
#endif
}

} // extern "C"