#ifndef	_SYS_TIMERFD_H
#define	_SYS_TIMERFD_H	1

#include <time.h>

#ifndef __THROW
  #ifdef __cplusplus
    #define __THROW throw()
  #else
    #define __THROW
  #endif
#endif

/* Bits to be set in the FLAGS parameter of `timerfd_create'.  */
#define	TFD_CLOEXEC		02000000
#define	TFD_NONBLOCK		00004000

/* Bits to be set in the FLAGS parameter of `timerfd_settime'.  */
#define	TFD_TIMER_ABSTIME	(1 << 0)

__BEGIN_DECLS
int timerfd_create (clockid_t clock_id, int flags) __THROW;
int timerfd_settime (int fd, int flags, const struct itimerspec *value,
    struct itimerspec *ovalue) __THROW;
int timerfd_gettime (int fd, struct itimerspec *value) __THROW;
__END_DECLS

#endif /* _SYS_TIMERFD_H */
