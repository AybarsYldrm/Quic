#pragma once
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

bool net_init();
int  udp_socket_ipv4_fd();
bool sock_bind_any_ipv4_fd(int fd, uint16_t port);
bool sock_connect_ipv4_fd(int fd, const char* host, uint16_t port);
bool sock_set_nonblock_fd(int fd);
void sock_close_fd(int fd);

#ifdef __cplusplus
}
#endif