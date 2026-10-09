#pragma once

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>

/// Opens /dev/pf (root only). Returns fd or -1.
int pg_pf_open(void);

/// Looks up the original destination of a connection redirected by a pf `rdr` rule.
/// `src` is the peer address of the accepted socket, `dst` its local address.
/// Returns 0 on success or an errno value.
int pg_natlook(int pf_fd, const struct sockaddr *src, const struct sockaddr *dst, struct sockaddr_storage *orig);

/// Finds the pid owning a TCP socket with the given local / foreign ports (host byte order).
/// `hints` are pids checked first. Returns pid or -1.
int pg_find_tcp_owner(uint16_t lport, uint16_t fport, const int32_t *hints, int nhints);

/// Executable path of a process. Returns length or <= 0 on failure.
int pg_pid_path(int32_t pid, char *buf, uint32_t size);
