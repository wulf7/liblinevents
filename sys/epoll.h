#ifndef	_LINEVENTS_EPOLL_H
#define	_LINEVENTS_EPOLL_H	1

#include <stdint.h>
#include <sys/types.h>
#include <signal.h>

#ifndef __THROW
  #ifdef __cplusplus
    #define __THROW throw()
  #else
    #define __THROW
  #endif
#endif

#define	EPOLL_CLOEXEC 02000000

#define	EPOLLIN		0x001
#define	EPOLLPRI	0x002
#define	EPOLLOUT	0x004
#define	EPOLLRDNORM	0x040
#define	EPOLLRDBAND	0x080
#define	EPOLLWRNORM	0x100
#define	EPOLLWRBAND	0x200
#define	EPOLLMSG	0x400
#define	EPOLLERR	0x008
#define	EPOLLHUP	0x010
#define	EPOLLRDHUP	0x2000
#define	EPOLLWAKEUP	(1u<<29)
#define	EPOLLONESHOT	(1u<<30)
#define	EPOLLET		(1u<<31)

#define	EPOLL_CTL_ADD	1
#define	EPOLL_CTL_DEL	2
#define	EPOLL_CTL_MOD	3

typedef union epoll_data {
	void *ptr;
	int fd;
	uint32_t u32;
	uint64_t u64;
} epoll_data_t;

struct epoll_event {
	uint32_t events;
	epoll_data_t data;
}
#if defined(__amd64__)
__attribute__((packed))
#endif
;


__BEGIN_DECLS

int epoll_create (int size) __THROW;
int epoll_create1 (int flags) __THROW;
int epoll_ctl (int epfd, int op, int fd, struct epoll_event *event) __THROW;
int epoll_wait (int epfd, struct epoll_event *events, int maxevents,
    int timeout);
int epoll_pwait (int epfd, struct epoll_event *events, int maxevents,
    int timeout, const sigset_t *uset);

__END_DECLS

#endif /* _LINEVENTS_EPOLL_H */
