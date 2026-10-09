#include "csys.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libproc.h>
#include <sys/proc_info.h>

// Mirrors xnu bsd/net/pfvar.h (private header, not shipped in the SDK).
union pg_state_xport {
    uint16_t port;
    uint16_t call_id;
    uint32_t spi;
};

struct pg_pfioc_natlook {
    uint8_t saddr[16];
    uint8_t daddr[16];
    uint8_t rsaddr[16];
    uint8_t rdaddr[16];
    union pg_state_xport sxport;
    union pg_state_xport dxport;
    union pg_state_xport rsxport;
    union pg_state_xport rdxport;
    uint8_t af;
    uint8_t proto;
    uint8_t proto_variant;
    uint8_t direction;
};

_Static_assert(sizeof(struct pg_pfioc_natlook) == 84, "pfioc_natlook layout");

#define PG_DIOCNATLOOK _IOWR('D', 23, struct pg_pfioc_natlook)
#define PG_PF_OUT 2

int pg_pf_open(void) {
    return open("/dev/pf", O_RDWR | O_CLOEXEC);
}

int pg_natlook(int pf_fd, const struct sockaddr *src, const struct sockaddr *dst, struct sockaddr_storage *orig) {
    struct pg_pfioc_natlook nl;
    memset(&nl, 0, sizeof(nl));
    memset(orig, 0, sizeof(*orig));

    if (src->sa_family == AF_INET && dst->sa_family == AF_INET) {
        const struct sockaddr_in *s = (const struct sockaddr_in *)(const void *)src;
        const struct sockaddr_in *d = (const struct sockaddr_in *)(const void *)dst;
        memcpy(nl.saddr, &s->sin_addr, 4);
        memcpy(nl.daddr, &d->sin_addr, 4);
        nl.sxport.port = s->sin_port;
        nl.dxport.port = d->sin_port;
        nl.af = AF_INET;
    } else if (src->sa_family == AF_INET6 && dst->sa_family == AF_INET6) {
        const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)(const void *)src;
        const struct sockaddr_in6 *d = (const struct sockaddr_in6 *)(const void *)dst;
        memcpy(nl.saddr, &s->sin6_addr, 16);
        memcpy(nl.daddr, &d->sin6_addr, 16);
        nl.sxport.port = s->sin6_port;
        nl.dxport.port = d->sin6_port;
        nl.af = AF_INET6;
    } else {
        return EAFNOSUPPORT;
    }
    nl.proto = IPPROTO_TCP;
    nl.direction = PG_PF_OUT;

    if (ioctl(pf_fd, PG_DIOCNATLOOK, &nl) == -1) {
        return errno;
    }

    if (src->sa_family == AF_INET) {
        struct sockaddr_in *o = (struct sockaddr_in *)(void *)orig;
        o->sin_len = sizeof(*o);
        o->sin_family = AF_INET;
        memcpy(&o->sin_addr, nl.rdaddr, 4);
        o->sin_port = nl.rdxport.port;
    } else {
        struct sockaddr_in6 *o = (struct sockaddr_in6 *)(void *)orig;
        o->sin6_len = sizeof(*o);
        o->sin6_family = AF_INET6;
        memcpy(&o->sin6_addr, nl.rdaddr, 16);
        o->sin6_port = nl.rdxport.port;
    }
    return 0;
}

static int pid_owns_socket(pid_t pid, uint16_t lport, uint16_t fport) {
    int size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
    if (size <= 0) {
        return 0;
    }
    size += 32 * PROC_PIDLISTFD_SIZE;
    struct proc_fdinfo *fds = malloc((size_t)size);
    if (fds == NULL) {
        return 0;
    }
    size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, size);
    int count = size > 0 ? size / PROC_PIDLISTFD_SIZE : 0;
    int found = 0;
    for (int i = 0; i < count && !found; i++) {
        if (fds[i].proc_fdtype != PROX_FDTYPE_SOCKET) {
            continue;
        }
        struct socket_fdinfo si;
        if (proc_pidfdinfo(pid, fds[i].proc_fd, PROC_PIDFDSOCKETINFO, &si, PROC_PIDFDSOCKETINFO_SIZE) != PROC_PIDFDSOCKETINFO_SIZE) {
            continue;
        }
        if (si.psi.soi_kind != SOCKINFO_TCP) {
            continue;
        }
        const struct in_sockinfo *in = &si.psi.soi_proto.pri_tcp.tcpsi_ini;
        if (ntohs((uint16_t)in->insi_lport) == lport && ntohs((uint16_t)in->insi_fport) == fport) {
            found = 1;
        }
    }
    free(fds);
    return found;
}

int pg_find_tcp_owner(uint16_t lport, uint16_t fport, const int32_t *hints, int nhints) {
    pid_t self = getpid();
    for (int i = 0; i < nhints; i++) {
        if (hints[i] > 0 && hints[i] != self && pid_owns_socket(hints[i], lport, fport)) {
            return hints[i];
        }
    }

    int capacity = proc_listallpids(NULL, 0);
    if (capacity <= 0) {
        return -1;
    }
    capacity += 128;
    pid_t *pids = malloc(sizeof(pid_t) * (size_t)capacity);
    if (pids == NULL) {
        return -1;
    }
    int count = proc_listallpids(pids, (int)sizeof(pid_t) * capacity);
    int result = -1;
    for (int i = 0; i < count; i++) {
        pid_t pid = pids[i];
        if (pid <= 0 || pid == self) {
            continue;
        }
        if (pid_owns_socket(pid, lport, fport)) {
            result = pid;
            break;
        }
    }
    free(pids);
    return result;
}

int pg_pid_path(int32_t pid, char *buf, uint32_t size) {
    return proc_pidpath(pid, buf, size);
}
