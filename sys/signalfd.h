#ifndef	_LINEVENTS_SIGNALFD_H
#define	_LINEVENTS_SIGNALFD_H	1

#include <signal.h>
#include <stdint.h>

#ifndef __THROW
  #ifdef __cplusplus
    #define __THROW throw()
  #else
    #define __THROW
  #endif
#endif

/* Flags for signalfd. */
#define	SFD_CLOEXEC	02000000
#define	SFD_NONBLOCK	00004000

struct signalfd_siginfo {
	uint32_t	ssi_signo;
	int32_t		ssi_errno;
	int32_t		ssi_code;
	uint32_t	ssi_pid;
	uint32_t	ssi_uid;
	int32_t		ssi_fd;
	uint32_t	ssi_tid;
	uint32_t	ssi_band;
	uint32_t	ssi_overrun;
	uint32_t	ssi_trapno;
	int32_t		ssi_status;
	int32_t		ssi_int;
	uint64_t	ssi_ptr;
	uint64_t	ssi_utime;
	uint64_t	ssi_stime;
	uint64_t	ssi_addr;
	uint8_t		__pad[48];
};

__BEGIN_DECLS
int signalfd(int fd, const sigset_t *set, int flags)
    __THROW __attribute__((nonnull(2)));
__END_DECLS

#endif /* _LINEVENTS_SIGNALFD_H */
